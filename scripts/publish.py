#!/usr/bin/env python3
"""Publish a checked, licensed, exact-tag candidate to an explicitly chosen repository."""
import argparse
from pathlib import Path
import re
import subprocess
import tomllib

from release import ROOT, digest, payload, verify_directory


def git(*arguments):
    return subprocess.run(['git', *arguments], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True, help='explicit GitHub OWNER/REPO')
    parser.add_argument('--tag', required=True)
    parser.add_argument('--artifacts', type=Path, default=ROOT / 'dist')
    parser.add_argument('--publish', action='store_true', help='create the GitHub prerelease after validation')
    args = parser.parse_args()
    package = tomllib.loads((ROOT / 'Cargo.toml').read_text())['package']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repo):
        raise SystemExit('Provide an explicit owner/repository')
    if not (ROOT / 'LICENSE').is_file() or not package.get('license'):
        raise SystemExit('Project license/repository selection is pending: add LICENSE and package.license first')
    if args.tag != 'v' + package['version']:
        raise SystemExit('Tag must match Cargo version')
    if git('status', '--porcelain') or git('rev-parse', 'HEAD') != git('rev-parse', args.tag + '^{commit}'):
        raise SystemExit('Use a clean checkout at the exact release tag')
    manifests = verify_directory(args.artifacts)
    if not all(m['version'] == package['version'] and m['project_license_selected'] for m in manifests):
        raise SystemExit('Artifacts are not the matching licensed candidate; rebuild')
    for manifest in manifests:
        for name, data in payload(ROOT, source=manifest['kind'] == 'source').items():
            if manifest['files'].get(name, {}).get('sha256') != digest(data):
                raise SystemExit('Artifact content differs from the tagged checkout: ' + name)
    if not args.publish:
        print(f'Validated {args.tag} for {args.repo}; pass --publish to create its GitHub prerelease')
        return
    names = [line.split('  ', 1)[1] for line in (args.artifacts / 'SHA256SUMS').read_text().splitlines()]
    subprocess.run(['gh', 'release', 'create', args.tag, '--repo', args.repo, '--verify-tag', '--prerelease',
                    '--title', 'Cloudflare Disk ' + package['version'], '--notes-file', str(ROOT / 'CHANGELOG.md'),
                    *(str(args.artifacts / name) for name in [*names, 'SHA256SUMS'])], check=True)


if __name__ == '__main__':
    main()
