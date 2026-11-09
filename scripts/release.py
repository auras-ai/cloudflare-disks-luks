#!/usr/bin/env python3
"""Explicit allowlist release packaging; never archive the checkout recursively."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ('__init__', 'cli', 'common', 'model', 'cloudflare', 'ledger', 'storage',
             'credentials', 'dependencies', 'firewall', 'host', 'verification', 'recovery')
COMMON = ('README.md', 'CHANGELOG.md', 'THIRD-PARTY-NOTICES.md', 'setup', 'config/example.toml',
          'packaging/cloudflare-disk.service', 'docs/CLIENT-SETUP.md', 'docs/OPERATIONS.md', 'docs/RELEASE.md',
          *('installer/' + name + '.py' for name in INSTALLER))
SOURCE = ('Cargo.toml', 'Cargo.lock', '.gitignore',
          *('src/' + name + '.rs' for name in ('lib', 'main', 'config', 'gateway', 'health', 'samba')),
          'tests/config_and_lifecycle.rs', 'tests/review_regressions.rs', 'tests/smb_roundtrip.sh',
          'tests/docker_smoke.py', 'tests/test_installer.py', 'tests/test_release.py',
          'scripts/release.py', 'scripts/publish.py', 'scripts/portable-build.sh', 'scripts/portable_build.py',
          '.github/workflows/ci.yml', '.github/workflows/release.yml')
EXECUTABLE = {'setup', 'bin/cloudflare-disk', 'scripts/portable-build.sh', 'scripts/portable_build.py',
              'scripts/release.py', 'scripts/publish.py', 'tests/smb_roundtrip.sh'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular(path):
    path = Path(path)
    for parent in [path, *path.parents]:
        if parent.is_symlink():
            raise ValueError('Release inputs cannot be symlinks: ' + str(path))
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('Release input must be a single-link regular file: ' + str(path))
    return path.read_bytes()


def payload(root, source):
    license_name = 'LICENSE' if (root / 'LICENSE').is_file() else 'LICENSE-PENDING.md'
    names = [*COMMON, license_name, *(SOURCE if source else ())]
    return {name: regular(root / name) for name in names}


def dependency_notices(root):
    metadata = json.loads(subprocess.run(['cargo', 'metadata', '--format-version', '1', '--locked', '--offline',
                         '--filter-platform', 'x86_64-unknown-linux-gnu'], cwd=root,
                         capture_output=True, text=True, check=True).stdout)
    resolved = {node['id'] for node in metadata['resolve']['nodes']}
    lock = tomllib.loads((root / 'Cargo.lock').read_text())
    checksums = {(p['name'], p['version']): p.get('checksum') for p in lock['package']}
    files, packages = {}, []
    for package in sorted(metadata['packages'], key=lambda p: (p['name'], p['version'])):
        if not package['source'] or package['id'] not in resolved:
            continue
        directory = Path(package['manifest_path']).parent
        candidates = [p for p in directory.iterdir() if p.is_file() and
                      p.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'COPYRIGHT', 'NOTICE'))]
        if package.get('license_file'):
            candidates.append(directory / package['license_file'])
        if not candidates:
            raise ValueError('Dependency license texts missing: ' + package['name'])
        license_files = []
        for path in sorted(set(candidates)):
            name = f'third-party/crates/{package["name"]}-{package["version"]}/{path.name}'
            files[name] = regular(path)
            license_files.append(name)
        packages.append({'name': package['name'], 'version': package['version'], 'license': package['license'],
                         'purl': f'pkg:cargo/{package["name"]}@{package["version"]}',
                         'checksum_sha256': checksums[(package['name'], package['version'])],
                         'license_files': license_files})
    files['SBOM.json'] = (json.dumps({'format': 'cloudflare-disk-dependency-inventory-v1',
                                    'target': 'x86_64-unknown-linux-gnu', 'packages': packages}, indent=2) + '\n').encode()
    return files


def validate_binary(path, version):
    data = regular(path)
    if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 62:
        raise ValueError('Expected Linux x86_64 little-endian ELF binary')
    symbols = subprocess.run(['objdump', '-T', path], capture_output=True, check=True).stdout
    versions = [tuple(map(int, match.split(b'.'))) for match in re.findall(rb'GLIBC_([0-9]+\.[0-9]+)', symbols)]
    if not versions or max(versions) > (2, 36):
        raise ValueError('Binary requires glibc newer than 2.36; use scripts/portable-build.sh')
    info = json.loads(regular(path.parent / 'BUILD-INFO.json'))
    if info['binary_sha256'] != digest(data) or info['bookworm_execution'] != f'cloudflare-disk {version}':
        raise ValueError('Portable build attestation/version does not match the binary')
    expected = {'Cargo.toml', 'Cargo.lock', *('src/' + name + '.rs' for name in ('lib', 'main', 'config', 'gateway', 'health', 'samba'))}
    if set(info['source_sha256']) != expected:
        raise ValueError('Build source inventory is incomplete')
    for name, sha in info['source_sha256'].items():
        if name not in SOURCE or digest(regular(ROOT / name)) != sha:
            raise ValueError('Binary was built from different sources; rebuild')
    return data, info


def write_archive(destination, prefix, files, *, version, kind, licensed):
    manifest = {'schema': 1, 'version': version, 'kind': kind, 'project_license_selected': licensed,
                'files': {name: {'sha256': digest(data), 'mode': '0755' if name in EXECUTABLE else '0644'}
                          for name, data in sorted(files.items())}}
    files = {**files, 'RELEASE-MANIFEST.json': (json.dumps(manifest, indent=2) + '\n').encode()}
    # Exclusive output: keep earlier artifacts intact until the operator deliberately replaces them.
    with destination.open('xb') as output, gzip.GzipFile(filename='', fileobj=output, mode='wb', mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode='w', format=tarfile.PAX_FORMAT) as archive:
            for name, data in sorted(files.items()):
                path = PurePosixPath(name)
                if path.is_absolute() or '..' in path.parts:
                    raise ValueError('Unsafe archive member')
                entry = tarfile.TarInfo(prefix + '/' + name)
                entry.size, entry.mode, entry.mtime = len(data), 0o755 if name in EXECUTABLE else 0o644, 0
                entry.uid = entry.gid = 0
                entry.uname = entry.gname = 'root'
                archive.addfile(entry, io.BytesIO(data))


def verify_archive(path):
    with tarfile.open(path, 'r:gz') as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if len(set(names)) != len(names) or not all(m.isfile() and not m.issym() and not m.islnk() for m in members):
            raise ValueError('Duplicate/nonregular archive members')
        prefixes = {PurePosixPath(name).parts[0] for name in names}
        if len(prefixes) != 1:
            raise ValueError('Archive has multiple roots')
        prefix = prefixes.pop()
        content = {}
        modes = {}
        for member in members:
            name = str(PurePosixPath(member.name).relative_to(prefix))
            if '..' in PurePosixPath(name).parts or member.name.startswith('/'):
                raise ValueError('Unsafe archive path')
            content[name] = archive.extractfile(member).read()
            modes[name] = f'{member.mode:04o}'
        manifest = json.loads(content.pop('RELEASE-MANIFEST.json'))
        if set(content) != set(manifest['files']):
            raise ValueError('Archive inventory mismatch')
        for name, data in content.items():
            if manifest['files'][name] != {'sha256': digest(data), 'mode': modes[name]}:
                raise ValueError('Archive hash/mode mismatch: ' + name)
            if name not in {*COMMON, *SOURCE, 'LICENSE', 'LICENSE-PENDING.md', 'SBOM.json', 'BUILD-INFO.json',
                            'bin/cloudflare-disk'} and not name.startswith('third-party/'):
                raise ValueError('File outside release allowlist: ' + name)
        return manifest


def verify_directory(directory):
    sums = (directory / 'SHA256SUMS').read_text().splitlines()
    checked = []
    for line in sums:
        checksum, name = line.split('  ', 1)
        if Path(name).name != name or not name.endswith('.tar.gz'):
            raise ValueError('Unsafe checksum filename')
        path = directory / name
        if digest(regular(path)) != checksum:
            raise ValueError('Archive checksum mismatch: ' + name)
        checked.append(verify_archive(path))
    if len(checked) != 2 or {m['kind'] for m in checked} != {'source', 'linux-x86_64-gnu'}:
        raise ValueError('Expected exactly one source and one Linux binary archive')
    return checked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/portable/cloudflare-disk')
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    parser.add_argument('--verify', type=Path)
    parser.add_argument('--require-license', action='store_true')
    args = parser.parse_args()
    if args.verify:
        verified = verify_directory(args.verify)
        print('Verified release checksums, allowlists, file hashes and permissions:', len(verified), 'archives')
        return
    package = tomllib.loads((ROOT / 'Cargo.toml').read_text())['package']
    version = package['version']
    licensed = (ROOT / 'LICENSE').is_file() and bool(package.get('license'))
    if args.require_license and not licensed:
        raise SystemExit('Choose LICENSE and Cargo package.license before public release packaging')
    binary, info = validate_binary(args.binary.resolve(), version)
    notices = dependency_notices(ROOT)
    rust = args.binary.resolve().parent / 'rust-notices'
    notices['third-party/rust/COPYRIGHT-library.html'] = regular(rust / 'COPYRIGHT-library.html')
    for path in sorted((rust / 'licenses').glob('*.txt')):
        notices['third-party/rust/licenses/' + path.name] = regular(path)
    if not (rust / 'licenses/MIT.txt').is_file() or not (rust / 'licenses/Apache-2.0.txt').is_file():
        raise ValueError('Rust standard library license texts missing')
    args.output.mkdir(parents=True, exist_ok=True)
    names = [f'cloudflare-disk-{version}-{kind}.tar.gz' for kind in ('source', 'linux-x86_64-gnu')]
    if any((args.output / name).exists() for name in [*names, 'SHA256SUMS']):
        raise SystemExit('Output artifacts already exist; use a new --output directory')
    for kind, name in zip(('source', 'linux-x86_64-gnu'), names):
        files = {**payload(ROOT, source=kind == 'source'), **notices}
        if kind != 'source':
            files['bin/cloudflare-disk'] = binary
            files['BUILD-INFO.json'] = (json.dumps(info, indent=2) + '\n').encode()
        write_archive(args.output / name, name.removesuffix('.tar.gz'), files,
                      version=version, kind=kind, licensed=licensed)
    (args.output / 'SHA256SUMS').write_text(''.join(f'{digest((args.output / name).read_bytes())}  {name}\n' for name in names))
    verify_directory(args.output)
    print('Prepared and verified:', args.output)


if __name__ == '__main__':
    main()
