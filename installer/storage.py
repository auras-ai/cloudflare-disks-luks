"""Provision a new bounded LUKS2 image, or unlock its exact recorded identity."""
import json
import os
from pathlib import Path
import re
import shutil
import stat

from .common import hidden, install_same, no_symlinks, private_dir, require, run
from .model import GIB


class Storage:
    def __init__(self, paths, ledger):
        self.paths, self.ledger = paths, ledger

    def probe(self, device):
        result = run(['blkid', '-p', '-o', 'export', device], check=False)
        require(result.returncode in (0, 2), 'Cannot identify storage signatures')
        return dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)

    def backing(self):
        rows = json.loads(run(['findmnt', '-J', '-T', self.paths.base, '-o', 'FSTYPE,UUID']).stdout)['filesystems']
        require(len(rows) == 1 and rows[0].get('fstype') in ('ext4', 'xfs', 'btrfs') and rows[0].get('uuid'),
                'The image requires a local ext4, XFS or Btrfs filesystem with a stable UUID')
        return rows[0]

    def check_image_identity(self, info):
        identity = self.ledger.get('image_identity', {})
        require(identity.get('inode') == info.st_ino,
                'Image identity differs or allocation was interrupted before recording; inspect manually')
        # st_dev (notably Btrfs anonymous device IDs) can change after reboot.
        # Pin the backing filesystem UUID and inode; the LUKS UUID is checked too.
        require(identity.get('backing_uuid') == self.backing()['uuid'], 'Image backing filesystem UUID differs')

    def check_image(self):
        path = no_symlinks(self.paths.image)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'Unsafe encrypted image file')
        self.check_image_identity(info)
        require(info.st_size == self.ledger.plan.size_gib * GIB, 'Image size differs from the recorded allocation')

    def allocate(self):
        p, log = self.paths, self.ledger
        size = log.plan.size_gib * GIB
        if log.get('allocated'):
            self.check_image()
            return
        if not p.image.exists():
            require(not log.get('image_identity'), 'Recorded image is missing; restore it, never recreate it')
            backing = self.backing()
            require(shutil.disk_usage(p.base).free >= size + 4 * GIB, 'Insufficient free space: image plus 4 GiB headroom required')
            fd = os.open(no_symlinks(p.image), os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.fsync(fd)
                info = os.fstat(fd)
                log.set(image_identity={'inode': info.st_ino, 'backing_uuid': backing['uuid']},
                        backing_filesystem=backing['fstype'])
            finally:
                os.close(fd)
        info = p.image.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= size,
                'Unrecognized partial image; refusing to modify it')
        self.check_image_identity(info)
        require(not self.probe(p.image), 'Image already has a signature; refusing allocation')
        if log.get('backing_filesystem') == 'btrfs':
            if info.st_size == 0:
                run(['chattr', '+C', p.image])
            flags = run(['lsattr', '-d', p.image]).stdout.decode().split()
            require(flags and 'C' in flags[0], 'Btrfs image must have No_COW before allocation; inspect partial allocation')
        fd = os.open(p.image, os.O_RDWR | os.O_NOFOLLOW)
        try:
            os.posix_fallocate(fd, 0, size)
            os.fsync(fd)
        finally:
            os.close(fd)
        log.set(allocated=True)
        self.check_image()

    def attach(self):
        self.check_image()
        loops = run(['losetup', '--associated', self.paths.image, '--noheadings', '--output', 'NAME']).stdout.decode().split()
        require(len(loops) <= 1, 'Multiple loop mappings for the image; inspect manually')
        loop = loops[0] if loops else run(['losetup', '--find', '--show', self.paths.image]).stdout.decode().strip()
        require(bool(re.fullmatch('/dev/loop[0-9]+', loop)), 'Unexpected loop device')
        # Association was selected by the kernel from the exact protected image.
        return loop

    def udev_rule(self):
        identity = self.ledger.get('luks_uuid')
        # Install before attach/format, including the not-yet-formatted loop case.
        text = ('# Owned by cloudflare-disk setup; manual unlock only.\n'
                f'SUBSYSTEM=="block", ATTR{{loop/backing_file}}=="{self.paths.image}", ENV{{UDISKS_IGNORE}}="1"\n'
                f'SUBSYSTEM=="block", ENV{{ID_FS_UUID}}=="{identity}", ENV{{UDISKS_IGNORE}}="1"\n'
                f'SUBSYSTEM=="block", ENV{{DM_UUID}}=="CRYPT-LUKS2-{identity.replace("-", "")}*", ENV{{UDISKS_IGNORE}}="1"\n')
        install_same(self.paths.udev, text, mode=0o644)
        run(['udevadm', 'control', '--reload-rules'])

    def check_mapping(self, loop):
        status = run(['cryptsetup', 'status', self.paths.mapper.name]).stdout.decode()
        device = next((line.split(':', 1)[1].strip() for line in status.splitlines()
                       if line.strip().startswith('device:')), None)
        require(device == loop and 'LUKS2' in status, 'Mapping does not belong to the recorded LUKS2 image')

    def open(self, loop, passphrase=None):
        require(run(['cryptsetup', 'luksUUID', loop]).stdout.decode().strip() == self.ledger.get('luks_uuid'),
                'LUKS UUID differs; refusing to unlock')
        if self.paths.mapper.exists():
            self.check_mapping(loop)
            return
        require(not list((Path('/sys/block') / Path(loop).name / 'holders').iterdir()),
                'Image has another mapping (possibly desktop auto-unlock); inspect before resuming')
        passphrase = passphrase or hidden('Existing LUKS passphrase')
        run(['cryptsetup', 'open', '--type', 'luks2', '--key-file', '-', loop, self.paths.mapper.name],
            data=passphrase.encode(), timeout=180)
        self.check_mapping(loop)

    def verify_mount(self):
        result = run(['findmnt', '-J', '--mountpoint', self.paths.storage, '-o', 'TARGET,SOURCE,FSTYPE,UUID,OPTIONS'], check=False)
        if result.returncode == 1 and not result.stdout:
            return False
        require(result.returncode == 0, 'Cannot inspect storage mount')
        rows = json.loads(result.stdout)['filesystems']
        require(len(rows) == 1, 'Ambiguous storage mount')
        row = rows[0]
        require(row['target'] == str(self.paths.storage) and row['fstype'] == 'ext4'
                and row['uuid'] == self.ledger.get('filesystem_uuid')
                and os.stat(row['source']).st_rdev == self.paths.mapper.stat().st_rdev
                and {'rw', 'nodev', 'nosuid'} <= set(row['options'].split(',')),
                'Storage mount identity or mount options differ')
        return True

    def mount(self):
        require(self.probe(self.paths.mapper).get('UUID') == self.ledger.get('filesystem_uuid'),
                'Filesystem identity differs')
        if not self.verify_mount():
            private_dir(self.paths.storage)
            require(not any(self.paths.storage.iterdir()), 'Storage underlay is not empty')
            checked = run(['e2fsck', '-p', self.paths.mapper], check=False, timeout=600)
            require(checked.returncode in (0, 1), 'Filesystem needs manual repair; retain image and keys')
            run(['mount', '-o', 'nodev,nosuid', self.paths.mapper, self.paths.storage])
            require(self.verify_mount(), 'Encrypted mount did not appear')
        os.chmod(self.paths.storage, 0o755)

    def provision(self):
        self.allocate()
        self.udev_rule()
        loop = self.attach()
        signature = self.probe(loop)
        passphrase = None
        if signature:
            require(signature.get('TYPE') == 'crypto_LUKS' and signature.get('UUID') == self.ledger.get('luks_uuid'),
                    'Existing image signature differs; formatting refused')
        else:
            require(not self.ledger.get('luks_format_started'),
                    'LUKS formatting was interrupted; inspect the image manually, no automatic reformat')
            passphrase = hidden('New LUKS passphrase', minimum=16, confirm=True)
            self.ledger.set(luks_format_started=True)
            run(['cryptsetup', 'luksFormat', '--batch-mode', '--type', 'luks2', '--uuid',
                 self.ledger.get('luks_uuid'), '--key-file', '-', loop], data=passphrase.encode(), timeout=300)
        self.ledger.set(luks_ready=True)
        self.open(loop, passphrase)
        signature = self.probe(self.paths.mapper)
        if signature:
            require(signature.get('TYPE') == 'ext4' and signature.get('UUID') == self.ledger.get('filesystem_uuid'),
                    'Existing filesystem differs; formatting refused')
        else:
            require(not self.ledger.get('filesystem_format_started'),
                    'Filesystem formatting was interrupted; inspect manually, no automatic reformat')
            self.ledger.set(filesystem_format_started=True)
            run(['mkfs.ext4', '-m', '1', '-U', self.ledger.get('filesystem_uuid'), self.paths.mapper], timeout=600)
        self.ledger.set(filesystem_ready=True)
        self.mount()

    def unlock(self):
        require(self.ledger.get('filesystem_ready'), 'Storage setup incomplete; use setup resume')
        self.open(self.attach())
        self.mount()
