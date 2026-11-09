"""Offline recovery bundle: authenticated GPG symmetric encryption, no plaintext export."""
import hashlib
import json
from pathlib import Path
import tarfile
import tempfile

from .common import atomic_write, hidden, install_same, no_symlinks, read_private, require, run, write_json
from .model import profile_text

RECOVERY_README = '''Cloudflare disk recovery bundle

secrets.toml includes the R2 credential, SMB password, crypt password AND salt.
profile.toml contains the matching immutable prefix/key identity and crypt mode.
luks-header.bin is a LUKS2 header backup; the LUKS passphrase is NOT included.
storage.json describes the local image and volume UUIDs.
setup.json is the nonsecret installation journal, not a replacement for the image.

Keep this bundle and its encryption passphrase on independent protected storage.
To decrypt: gpg --output recovery.tar --decrypt recovery.tar.gpg
Extract only into a private directory on encrypted storage. Do not upload keys to support.
Recover uploaded files using an isolated rclone crypt reader with these exact keys,
standard filename encryption and encrypted directory names. Never run sync/delete.
LUKS header restoration must be tested on an image clone, never on a live volume.
Pending writes require the original local image/cache, not just this bundle.
This bundle contains keys and metadata, NOT a backup of client files.
See docs/OPERATIONS.md in the release for detailed recovery procedures.
'''


def prepare(paths, ledger, material):
    uid, gid = ledger.get('service_uid'), ledger.get('service_gid')
    text = profile_text(ledger.plan, ledger.get('key_id'), paths)
    encoded = ''.join(f'{key} = {json.dumps(value, ensure_ascii=False)}\n' for key, value in material.items())
    # Individually atomic, no regeneration or overwrite after either file lands.
    install_same(paths.state / 'secrets.toml', encoded, uid=uid, gid=gid)
    install_same(paths.profile, text, uid=uid, gid=gid)
    install_same(paths.recovery / 'secrets.toml', encoded)
    install_same(paths.recovery / 'profile.toml', text)
    install_same(paths.recovery / 'README.txt', RECOVERY_README)
    header = paths.recovery / 'luks-header.bin'
    if not header.exists():
        with tempfile.TemporaryDirectory(prefix='header-', dir=paths.recovery) as temporary:
            candidate = Path(temporary) / 'header.bin'
            run(['cryptsetup', 'luksHeaderBackup', paths.image, '--header-backup-file', candidate])
            atomic_write(header, candidate.read_bytes())
    require(run(['cryptsetup', 'luksUUID', header]).stdout.decode().strip() == ledger.get('luks_uuid'),
            'Recovery header UUID differs')
    storage = {'image': str(paths.image), 'mount': str(paths.storage),
               'luks_uuid': ledger.get('luks_uuid'), 'filesystem_uuid': ledger.get('filesystem_uuid')}
    install_same(paths.recovery / 'storage.json', json.dumps(storage, indent=2) + '\n')
    ledger.set(profile_ready=True)


def export(paths, ledger, destination):
    destination = no_symlinks(Path(destination))
    require(destination.parent.is_dir() and not destination.exists(), 'Use a new recovery filename in an existing directory')
    require(ledger.get('profile_ready'), 'Setup must save its profile and keys before export')
    passphrase = hidden('New recovery archive passphrase', minimum=16, confirm=True)
    with tempfile.TemporaryDirectory(prefix='export-', dir=paths.recovery) as temporary:
        work = Path(temporary)
        home = work / 'gnupg'
        home.mkdir(mode=0o700)
        tar = work / 'recovery.tar'
        write_json(work / 'setup.json', ledger.data)
        with tarfile.open(tar, 'w') as archive:
            for name in ('profile.toml', 'secrets.toml', 'luks-header.bin', 'storage.json', 'README.txt'):
                path = paths.recovery / name
                read_private(path, limit=32 * 1024**2)
                archive.add(path, arcname=name, recursive=False)
            archive.add(work / 'setup.json', arcname='setup.json', recursive=False)
            if (paths.recovery / 'acceptance.json').exists():
                archive.add(paths.recovery / 'acceptance.json', arcname='acceptance.json', recursive=False)
        arguments = ['gpg', '--no-options', '--homedir', home, '--batch', '--pinentry-mode', 'loopback',
                     '--passphrase-fd', '0', '--no-symkey-cache']
        try:
            encrypted = run([*arguments, '--cipher-algo', 'AES256', '--s2k-mode', '3',
                             '--s2k-digest-algo', 'SHA256', '--output', '-', '--symmetric', tar],
                            data=(passphrase + '\n').encode()).stdout
            atomic_write(work / 'recovery.tar.gpg', encrypted)
            decrypted = run([*arguments, '--decrypt', work / 'recovery.tar.gpg'], data=(passphrase + '\n').encode()).stdout
            require(hashlib.sha256(decrypted).digest() == hashlib.sha256(tar.read_bytes()).digest(),
                    'Encrypted recovery archive failed its readback check')
            atomic_write(destination, encrypted)
        finally:
            run(['gpgconf', '--homedir', home, '--kill', 'gpg-agent'], check=False)
    ledger.set(recovery_exported=True)
    return destination
