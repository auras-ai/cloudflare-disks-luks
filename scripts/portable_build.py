#!/usr/bin/env python3
"""Build on glibc 2.36 without mounting the deployment checkout into Docker."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e'
SOURCES = ['Cargo.toml', 'Cargo.lock', *['src/' + name + '.rs' for name in
           ('lib', 'main', 'config', 'gateway', 'health', 'samba')]]


def main():
    output = ROOT / 'target/portable'
    output.mkdir(parents=True, exist_ok=True)
    offline = os.environ.get('CLOUDFLARE_DISK_OFFLINE_BUILD') == '1'
    temporary_root = os.environ.get('TMPDIR') or ('/tmp/opencode' if Path('/tmp/opencode').is_dir() else None)
    with tempfile.TemporaryDirectory(prefix='cloudflare-disk-build-', dir=temporary_root) as temporary:
        stage = Path(temporary)
        for name in SOURCES:
            source = ROOT / name
            if source.is_symlink():
                raise SystemExit('Refusing symlink source: ' + name)
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        (stage / 'home').mkdir()
        cargo = stage / 'cargo-home'
        cargo.mkdir()
        if offline:
            registry = Path(os.environ.get('CARGO_HOME', str(Path.home() / '.cargo'))) / 'registry'
            for name in ('src', 'cache', 'index'):
                shutil.copytree(registry / name, cargo / 'registry' / name)
        script = '''
mkdir -p /work
tar -xf - -C /work
cd /work
cargo build --release --locked "$@" >&2
mkdir -p /out
cp target/release/cloudflare-disk /out/cloudflare-disk
rustc --version > /out/rustc.txt
sysroot=$(rustc --print sysroot)
mkdir -p /out/rust-notices/licenses
cp "$sysroot/share/doc/rust/COPYRIGHT-library.html" /out/rust-notices/
cp "$sysroot"/share/doc/rust/licenses/*.txt /out/rust-notices/licenses/
tar -cf - -C /out .
'''
        source_tar, result_tar = stage / 'input.tar', stage / 'output.tar'
        with tarfile.open(source_tar, 'w') as archive:
            for name in ('Cargo.toml', 'Cargo.lock', 'src', 'home', 'cargo-home'):
                archive.add(stage / name, arcname=name)
        # Streaming avoids both host-path visibility and stopped-container overlay
        # mount races in rootless Docker. Only the selected files enter the daemon.
        with source_tar.open('rb') as source, result_tar.open('wb') as destination:
            subprocess.run(['docker', 'run', '--rm', '--interactive', '--network', 'none' if offline else 'default',
                            '-e', 'CARGO_HOME=/work/cargo-home', '-e', 'HOME=/work/home',
                            IMAGE, 'bash', '-euc', script, 'build', *(['--offline'] if offline else [])],
                           stdin=source, stdout=destination, check=True)
        with tarfile.open(result_tar) as archive:
            for member in archive.getmembers():
                name = PurePosixPath(member.name)
                if name.is_absolute() or '..' in name.parts or not (member.isdir() or member.isfile()):
                    raise SystemExit('Unexpected build output path/type')
                if member.isdir():
                    continue
                allowed = str(name) in ('cloudflare-disk', 'rustc.txt', 'rust-notices/COPYRIGHT-library.html')
                allowed |= str(name).startswith('rust-notices/licenses/') and name.suffix == '.txt'
                if not allowed:
                    raise SystemExit('Unexpected build output file')
                target = output / str(name)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
                target.chmod(0o755 if str(name) == 'cloudflare-disk' else 0o644)
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text())['package']['version']
    with (output / 'cloudflare-disk').open('rb') as executable:
        result = subprocess.run(['docker', 'run', '--rm', '--interactive', '--network', 'none',
                                 'debian:bookworm-slim', 'sh', '-ec',
                                 'cat > /usr/local/bin/cloudflare-disk\nchmod 755 /usr/local/bin/cloudflare-disk\nexec /usr/local/bin/cloudflare-disk --version'],
                                stdin=executable, capture_output=True, text=True, check=True)
    if result.stdout.strip() != f'cloudflare-disk {version}':
        raise SystemExit('Portable binary version mismatch')
    info = {'builder': IMAGE, 'rustc': (output / 'rustc.txt').read_text().strip(),
            'target': 'x86_64-unknown-linux-gnu', 'maximum_glibc': '2.36',
            'source_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES},
            'binary_sha256': hashlib.sha256((output / 'cloudflare-disk').read_bytes()).hexdigest(),
            'bookworm_execution': result.stdout.strip()}
    (output / 'BUILD-INFO.json').write_text(json.dumps(info, indent=2) + '\n')
    print('Portable build and Debian Bookworm execution passed:', output)


if __name__ == '__main__':
    main()
