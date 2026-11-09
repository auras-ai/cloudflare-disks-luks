"""Opt-in disposable encrypted SMB smoke test and independent crypt reader.

R2_TEST_PREFIX must exactly equal the gateway encryption prefix. R2_TEST_BACKUP
is a protected TOML secrets backup, not gateway/cache access. R2_TEST_SCRATCH
must be a private directory on administrator-provisioned disposable LUKS storage.
No recursive remote cleanup; failures retain objects and private scratch evidence.
"""
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import tempfile
import time
import tomllib
import uuid


class CryptReader:
    def __init__(self, profile, secrets):
        assert os.environ.get('R2_DISPOSABLE_TEST') == 'YES', 'explicit disposable opt-in required'
        self.bucket = profile['bucket']
        self.prefix = profile['encryption']['prefix']
        assert self.bucket == os.environ['R2_TEST_BUCKET']
        assert self.prefix == os.environ['R2_TEST_PREFIX']
        assert re.fullmatch(r'[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*', self.prefix)
        scratch = pathlib.Path(os.environ['R2_TEST_SCRATCH'])
        assert scratch.is_dir() and stat.S_IMODE(scratch.stat().st_mode) == 0o700
        self.work = pathlib.Path(tempfile.mkdtemp(prefix='crypt-reader-', dir=scratch))
        os.chmod(self.work, 0o700)
        self.config = self.work / 'rclone.conf'
        self.env = {'PATH': os.environ['PATH'], 'HOME': str(self.work), 'TMPDIR': str(self.work)}
        backup = pathlib.Path(os.environ['R2_TEST_BACKUP'])
        mode = backup.lstat()
        assert stat.S_ISREG(mode.st_mode) and stat.S_IMODE(mode.st_mode) == 0o600
        assert mode.st_uid == os.geteuid() and mode.st_nlink == 1
        keys = tomllib.loads(backup.read_text())
        def obscure(value):
            assert value and '\n' not in value and '\r' not in value
            result = subprocess.run(['rclone', '--config', os.devnull, 'obscure', '-'],
                                    input=value.encode(), capture_output=True, env=self.env, timeout=30)
            assert result.returncode == 0, 'rclone obscure failed (diagnostics suppressed)'
            return result.stdout.decode().strip()
        values = [profile['endpoint'], self.bucket, secrets['access_key_id'], secrets['secret_access_key']]
        assert all(not any(ch in v for ch in '\r\n') for v in values)
        self.text = ('[raw]\ntype = s3\nprovider = Cloudflare\nenv_auth = false\nno_check_bucket = true\n'
                     f'endpoint = {values[0]}\naccess_key_id = {values[2]}\nsecret_access_key = {values[3]}\n'
                     '[crypt]\ntype = crypt\n'
                     f'remote = raw:{self.bucket}/{self.prefix}\n'
                     'filename_encryption = standard\ndirectory_name_encryption = true\n'
                     f'password = {obscure(keys["crypt_password"])}\n'
                     f'password2 = {obscure(keys["crypt_salt"])}\n')
        self.config.write_text(self.text)
        self.config.chmod(0o600)
        print('Independent reader evidence:', self.work, flush=True)

    def run(self, *args, data=None, config=None, check=True):
        result = subprocess.run(['rclone', '--config', str(config or self.config),
                                 '--cache-dir', str(self.work / 'fresh-cache'), *args],
                                input=data, capture_output=True, env=self.env, timeout=180)
        if check:
            assert result.returncode == 0, 'independent rclone failed; remote evidence retained'
        return result

    def key(self, name):
        result = self.run('cryptdecode', '--reverse', 'crypt:', name).stdout.decode().strip()
        original, encrypted = result.split('\t', 1)
        encrypted = encrypted.strip()
        assert original.strip() == name
        assert len(encrypted.split('/')) == len(name.split('/'))
        assert all(re.fullmatch(r'[a-z0-9]+', part) for part in encrypted.split('/'))
        assert all(a != b for a, b in zip(name.split('/'), encrypted.split('/')))
        return self.prefix + '/' + encrypted

    def read(self, name):
        return self.run('cat', 'crypt:' + name).stdout

    def rejected_keys(self, name):
        for label, password in [('missing', ''), ('wrong', 'deliberately-wrong-backup-key')]:
            config = self.work / (label + '.conf')
            lines = self.text.splitlines()
            lines = [line for line in lines if not line.startswith('password = ')]
            if password:
                value = subprocess.run(['rclone', '--config', os.devnull, 'obscure', '-'],
                                       input=password.encode(), capture_output=True, env=self.env,
                                       timeout=30, check=True).stdout.decode().strip()
                lines.append('password = ' + value)
            config.write_text('\n'.join(lines) + '\n')
            config.chmod(0o600)
            # Read the SAME ciphertext name; listing with a wrong key is not proof.
            raw = self.work / 'ciphertext'
            self.run('copyto', 'raw:' + self.bucket + '/' + self.key(name), str(raw))
            local = self.work / ('local-' + label + '.conf')
            local.write_text(config.read_text().replace(
                f'remote = raw:{self.bucket}/{self.prefix}', f'remote = {self.work}/probe'))
            local.chmod(0o600)
            probe = self.work / 'probe'
            probe.mkdir(exist_ok=True)
            # Filename encryption disabled only for this content-authentication probe.
            local.write_text(local.read_text().replace('filename_encryption = standard',
                                                       'filename_encryption = off'))
            (probe / 'payload.bin').write_bytes(raw.read_bytes())
            good = self.work / 'local-good.conf'
            good.write_text(self.text.replace(
                f'remote = raw:{self.bucket}/{self.prefix}', f'remote = {probe}').replace(
                    'filename_encryption = standard', 'filename_encryption = off'))
            good.chmod(0o600)
            assert self.run('cat', 'crypt:payload', config=good).stdout == self.read(name)
            assert self.run('cat', 'crypt:payload', config=local, check=False).returncode != 0


def main():
    import boto3
    import smbclient
    from botocore.config import Config
    os.umask(0o077)
    state = pathlib.Path('/credentials')
    p = tomllib.loads((state / 'profile.toml').read_text())
    s = tomllib.loads((state / 'secrets.toml').read_text())
    reader = CryptReader(p, s)
    run = 'docker-smoke-' + uuid.uuid4().hex
    name = run + '/renamed.bin'
    key = reader.key(name)
    s3 = boto3.client('s3', endpoint_url=p['endpoint'], region_name='auto',
                      aws_access_key_id=s['access_key_id'], aws_secret_access_key=s['secret_access_key'],
                      config=Config(connect_timeout=5, read_timeout=30, retries={'max_attempts': 2}))
    assert not s3.list_objects_v2(Bucket=p['bucket'], Prefix=reader.key(run) + '/', MaxKeys=1).get('Contents')
    root = '\\\\gateway\\' + p['share'] + '\\' + run
    smbclient.register_session('gateway', username='r2disk', password=s['smb_password'], encrypt=True)
    smbclient.mkdir(root)
    data = os.urandom(2 * 1048576)
    with smbclient.open_file(root + '\\payload.bin', mode='wb') as f:
        f.write(data)
    smbclient.rename(root + '\\payload.bin', root + '\\renamed.bin')
    with smbclient.open_file(root + '\\renamed.bin', mode='rb') as f:
        assert f.read() == data
    deadline = time.monotonic() + 180
    while True:
        try:
            raw = s3.get_object(Bucket=p['bucket'], Key=key)['Body'].read()
            assert raw.startswith(b'RCLONE\x00\x00') and raw != data
            if reader.read(name) == data:
                break
        except s3.exceptions.NoSuchKey:
            pass
        assert time.monotonic() < deadline, 'upload timeout; evidence retained'
        time.sleep(1)
    reader.rejected_keys(name)
    # No gateway/cache used: reader configuration is reconstructed from the backup.
    assert reader.read(name) == data
    smbclient.remove(root + '\\renamed.bin')
    deadline = time.monotonic() + 60
    while True:
        try:
            s3.head_object(Bucket=p['bucket'], Key=key)
        except s3.exceptions.ClientError as error:
            assert error.response['Error']['Code'] in ('404', 'NoSuchKey')
            break
        assert time.monotonic() < deadline, 'delete timeout; evidence retained'
        time.sleep(1)
    smbclient.rmdir(root)
    print(json.dumps({'result': 'PASS', 'key': key, 'sha256': hashlib.sha256(data).hexdigest(),
                      'checks': ['SMB create/read/rename/delete', 'raw ciphertext',
                                 'backup-only independent restore', 'wrong/missing key refusal']}))


if __name__ == '__main__':
    main()
