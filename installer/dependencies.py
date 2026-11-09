"""Optional Ubuntu package install and checksum-pinned upstream rclone."""
import hashlib
import io
import os
from pathlib import Path
import platform
import re
import shutil
import urllib.request
import zipfile

from .common import SetupError, atomic_write, install_same, require, run

RCLONE_VERSION = '1.70.3'
RCLONE_SHA256 = '7d69057e69385f6514a9684c7eaa424d972096b130284bb34dd967c4ed4f9dad'
TOOLS = ('cryptsetup', 'losetup', 'mkfs.ext4', 'e2fsck', 'mount', 'findmnt', 'blkid', 'chattr', 'lsattr',
         'useradd', 'runuser', 'ip', 'systemctl', 'systemd-run', 'systemd-analyze', 'udevadm',
         'rclone', 'smbd', 'testparm', 'pdbedit', 'smbclient', 'fusermount3', 'nft', 'gpg', 'gpgconf')
POLICY = b'#!/bin/sh\n# cloudflare-disk dependency installation guard\n# fresh-samba: %s\nexit 101\n'


def version(program, argument, minimum):
    result = run([program, argument])
    found = re.search(rb'\b[vV]?([0-9]+)\.([0-9]+)(?:\.([0-9]+))?', result.stdout + result.stderr)
    require(found is not None and tuple(int(n or 0) for n in found.groups()) >= minimum,
            f'{program} is too old; need {".".join(map(str, minimum))} or newer')


def check():
    require(platform.system() == 'Linux', 'The gateway installer requires Linux')
    missing = [name for name in TOOLS if not shutil.which(name)]
    require(not missing, 'Missing dependencies: ' + ', '.join(missing) + '; Ubuntu 24.04: use install --install-deps')
    for program, argument, minimum in [('rclone', 'version', (1, 70, 0)),
                                        ('smbd', '--version', (4, 19, 0)),
                                        ('pdbedit', '--version', (4, 19, 0)),
                                        ('testparm', '--version', (4, 19, 0)),
                                        ('fusermount3', '--version', (3, 14, 0))]:
        version(program, argument, minimum)
    require(Path('/run/systemd/system').is_dir(), 'Boot a systemd Linux host; container-only setup is unsupported')
    require(Path('/dev/fuse').exists(), 'Kernel FUSE /dev/fuse is unavailable')


def install_rclone():
    if shutil.which('rclone'):
        try:
            version('rclone', 'version', (1, 70, 0))
            return
        except SetupError:
            pass
    require(platform.machine() == 'x86_64', 'Automatic rclone installation currently supports Linux x86_64')
    destination = Path('/usr/local/bin/rclone')
    require(not destination.exists(), 'Existing /usr/local/bin/rclone needs an operator-managed upgrade')
    archive = f'rclone-v{RCLONE_VERSION}-linux-amd64.zip'
    urls = [f'https://downloads.rclone.org/v{RCLONE_VERSION}/{archive}',
            f'https://github.com/rclone/rclone/releases/download/v{RCLONE_VERSION}/{archive}',
            'https://api.github.com/repos/rclone/rclone/releases/assets/271380706']
    data = None
    for url in urls:
        try:
            request = urllib.request.Request(url, headers={'Accept': 'application/octet-stream',
                                                          'User-Agent': 'cloudflare-disk-setup'})
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read(64 * 1024**2 + 1)
            break
        except OSError:
            continue
    require(data is not None, 'rclone download failed; install verified rclone >= 1.70 manually, then resume')
    require(hashlib.sha256(data).hexdigest() == RCLONE_SHA256, 'rclone archive checksum mismatch')
    with zipfile.ZipFile(io.BytesIO(data)) as source:
        member = source.getinfo(f'rclone-v{RCLONE_VERSION}-linux-amd64/rclone')
        require(member.file_size < 128 * 1024**2, 'Unexpected rclone executable size')
        atomic_write(destination, source.read(member), mode=0o755)


def install():
    distro = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(distro.get('ID', '').strip('"') == 'ubuntu' and distro.get('VERSION_ID', '').strip('"') == '24.04',
            'Automatic packages target Ubuntu 24.04; on other Linux hosts install the documented dependencies first')
    fresh_samba = shutil.which('smbd') is None
    # Do not let package scripts start an unconfigured network service.
    policy = Path('/usr/sbin/policy-rc.d')
    accepted = [POLICY % value for value in (b'yes', b'no')]
    require(not policy.exists() or policy.read_bytes() in accepted,
            'An existing policy-rc.d is managed by this host; install dependencies using its package policy')
    if policy.exists():
        fresh_samba = b'fresh-samba: yes' in policy.read_bytes()
    content = POLICY % (b'yes' if fresh_samba else b'no')
    install_same(policy, content, mode=0o755)
    completed = False
    try:
        run(['apt-get', 'update'], timeout=600)
        run(['apt-get', 'install', '-y', '--no-install-recommends', 'ca-certificates', 'cryptsetup',
             'e2fsprogs', 'util-linux', 'iproute2', 'samba', 'samba-common-bin', 'smbclient',
             'fuse3', 'nftables', 'gnupg'], timeout=1200,
            env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'})
        if fresh_samba:
            for unit in ('smbd.service', 'nmbd.service', 'samba-ad-dc.service'):
                run(['systemctl', 'disable', unit])
        completed = True
    finally:
        # An interrupted apt session retains its known guard/intent for the next run.
        if completed and policy.exists() and policy.read_bytes() == content:
            policy.unlink()
    install_rclone()
