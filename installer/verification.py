"""Encrypted SMB CRUD plus a fresh, independent R2 decrypt using recovery keys."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import tomllib
import uuid

from .common import atomic_write, read_private, require, run, write_json
from .host import PATH, as_service


def verify(paths, ledger):
    profile = tomllib.loads(read_private(paths.recovery / 'profile.toml').decode())
    keys = tomllib.loads(read_private(paths.recovery / 'secrets.toml').decode())
    work = Path(tempfile.mkdtemp(prefix='acceptance-', dir=paths.storage))
    name = 'setup-check-' + uuid.uuid4().hex
    environment = {'PATH': PATH, 'HOME': str(work), 'TMPDIR': str(work)}

    def command(args, data=None, check=True):
        return run(args, data=data, check=check, env=environment, timeout=40)

    def obscure(value):
        return command(['rclone', 'obscure', '--config', '/dev/null', '-'], value.encode()).stdout.decode().strip()

    auth = work / 'smb.auth'
    config = work / 'reader.conf'
    atomic_write(auth, 'username = r2disk\npassword = ' + keys['smb_password'] + '\n')
    atomic_write(config, '[raw]\ntype = s3\nprovider = Cloudflare\nregion = auto\nno_check_bucket = true\n'
                 f'endpoint = {profile["endpoint"]}\naccess_key_id = {keys["access_key_id"]}\n'
                 f'secret_access_key = {keys["secret_access_key"]}\n'
                 '[crypt]\ntype = crypt\nfilename_encryption = standard\ndirectory_name_encryption = true\n'
                 f'remote = raw:{profile["bucket"]}/{profile["encryption"]["prefix"]}\n'
                 f'password = {obscure(keys["crypt_password"])}\npassword2 = {obscure(keys["crypt_salt"])}\n')

    def rclone(*args, check=True):
        return command(['rclone', '--config', config, '--cache-dir', work / 'independent-cache',
                        '--retries', '1', '--low-level-retries', '1', *args], check=check)

    def smb(commands):
        return command(['smbclient', f'//{ledger.plan.address}/cloud', '--client-protection=encrypt',
                        '-A', auth, '-c', commands])

    success = False
    try:
        data = os.urandom(2 * 1024**2)
        atomic_write(work / 'original.bin', data)
        write_json(work / 'attempt.json', {'test_directory': name})
        smb(f'mkdir {name}; put {work}/original.bin {name}/original.bin; '
            f'rename {name}/original.bin {name}/renamed.bin; get {name}/renamed.bin {work}/readback.bin')
        require((work / 'readback.bin').read_bytes() == data, 'SMB readback differs; private evidence retained on encrypted storage')
        logical = name + '/renamed.bin'
        mapping = rclone('cryptdecode', '--reverse', 'crypt:', logical).stdout.decode().strip().split('\t', 1)
        require(len(mapping) == 2 and mapping[0].strip() == logical, 'Could not verify encrypted filename')
        encrypted_name = mapping[1].strip()
        require(encrypted_name != logical and len(encrypted_name.split('/')) == 2,
                'Unexpected encrypted filename mapping')
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            remote = rclone('cat', 'crypt:' + logical, check=False)
            if remote.returncode == 0 and remote.stdout == data:
                break
            time.sleep(1)
        else:
            require(False, 'Independent R2 decrypt did not match within 120 seconds; private evidence and test object retained')
        prefix = f'raw:{profile["bucket"]}/{profile["encryption"]["prefix"]}/'
        raw = rclone('cat', prefix + encrypted_name).stdout
        require(raw.startswith(b'RCLONE\0\0') and raw != data, 'R2 object is not expected rclone ciphertext')
        smb(f'del {name}/renamed.bin; rmdir {name}')
        # Check only the random test directory, not the client's entire bucket.
        require(not rclone('lsf', prefix + encrypted_name.split('/')[0], '--recursive').stdout.strip(),
                'Remote verification object still exists')
        health = json.loads(as_service(paths, 'status').stdout)
        require(all(health.get(k) for k in ('process_alive', 'mount_ready', 'backend_reachable'))
                and health.get('cache_pressure') is False
                and all(health.get(k) == 0 for k in ('pending_uploads', 'error_uploads', 'retrying_uploads', 'transfer_errors')),
                'File verification passed but gateway telemetry is not clean; inspect status')
        result = {'result': 'PASS', 'sha256': hashlib.sha256(data).hexdigest(), 'status': health,
                  'checks': ['encrypted SMB create/read/rename/delete', 'encrypted R2 names and contents',
                             'independent recovery-key decrypt with fresh cache', 'remote test object removed']}
        write_json(paths.recovery / 'acceptance.json', result, replace=True)
        ledger.set(verified=True)
        success = True
        return result
    finally:
        auth.unlink(missing_ok=True)
        config.unlink(missing_ok=True)
        if success:
            shutil.rmtree(work)
