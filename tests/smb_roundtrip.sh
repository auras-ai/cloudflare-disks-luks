#!/usr/bin/env bash
# Deliberately no implicit credentials, bucket, service control or recursive purge.
set -euo pipefail
umask 077
if [[ ${R2_DISPOSABLE_TEST:-} != YES ]]; then
    echo 'BLOCKED: set R2_DISPOSABLE_TEST=YES and read README test prerequisites' >&2
    exit 77
fi
[[ $(uname -s) == Linux ]] || { echo 'Linux required' >&2; exit 77; }
: "${R2_TEST_CREDENTIALS:?0600 JSON credentials file required}"
: "${R2_TEST_BUCKET:?explicit disposable bucket required}"
: "${R2_TEST_PREFIX:?explicit disposable parent prefix required}"
: "${R2_TEST_HOOK:?absolute executable dedicated-gateway fault/status hook required}"
: "${R2_TEST_NETWORK:?record client/gateway location, LAN/VPN, bandwidth/RTT and storage}"
command -v smbclient >/dev/null
command -v rclone >/dev/null
export R2_TEST_READER="$(dirname "$(realpath "$0")")/docker_smoke.py"
exec python3 -I - <<'PY'
import contextlib
import runpy

import json
import os
import pathlib
import random
import re
import stat
import subprocess
import tempfile
import time
import uuid

import boto3
import smbclient as smb  # pip install smbprotocol boto3
from botocore.config import Config
from botocore.exceptions import ClientError

bucket = os.environ['R2_TEST_BUCKET']
parent = os.environ['R2_TEST_PREFIX']
assert re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', bucket)
assert re.fullmatch(r'[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*', parent), 'unsafe prefix'
prefix = 'run-' + uuid.uuid4().hex
hook = pathlib.Path(os.environ['R2_TEST_HOOK'])
assert hook.is_absolute() and hook.is_file() and os.access(hook, os.X_OK)
credential = pathlib.Path(os.environ['R2_TEST_CREDENTIALS'])
m = credential.lstat()
assert stat.S_ISREG(m.st_mode) and stat.S_IMODE(m.st_mode) == 0o600
assert m.st_uid == os.geteuid() and m.st_nlink == 1
c = json.loads(credential.read_text())
assert re.fullmatch(r'https://[a-f0-9]{32}\.r2\.cloudflarestorage\.com', c['endpoint'])
assert re.fullmatch(r'[A-Za-z0-9.-]+', c['host'])
assert re.fullmatch(r'[A-Za-z0-9_-]+', c['share'])
assert all(not any(ch in str(v) for ch in '\r\n') for v in c.values())
reader = runpy.run_path(os.environ['R2_TEST_READER'])['CryptReader'](
    {'bucket': bucket, 'endpoint': c['endpoint'], 'encryption': {'prefix': parent}}, c)
work = reader.work
report = {'prefix': prefix, 'bucket': bucket, 'network': os.environ['R2_TEST_NETWORK'],
          'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
          'kernel': os.uname().release, 'metrics': [], 'checks': [], 'result': 'RUNNING'}
print('Private results:', work, 'remote scope:', bucket + '/' + prefix, flush=True)
(work / 'smb.auth').write_text('username = ' + c['username'] + '\npassword = ' + c['password'] + '\n')
os.chmod(work / 'smb.auth', 0o600)
s3 = boto3.client('s3', endpoint_url=c['endpoint'], region_name='auto',
                  aws_access_key_id=c['access_key_id'], aws_secret_access_key=c['secret_access_key'],
                  config=Config(connect_timeout=5, read_timeout=30, retries={'max_attempts': 2}))
root = '\\\\' + c['host'] + '\\' + c['share'] + '\\' + prefix.replace('/', '\\')
expected = {}
created = set()
authorized = False

def key(name):
    assert name and '/' not in name and '\\' not in name and name not in ('.', '..')
    return reader.key(prefix + '/' + name)

def path(name):
    key(name)
    return root + '\\' + name

def control(action):
    # Hook is explicitly operator-owned; never eval shell strings or infer a service/PID.
    p = subprocess.run([str(hook), action, bucket, prefix], check=False,
                       capture_output=True, text=True, timeout=180)
    with (work / 'hook.log').open('a') as f:
        f.write(action + '\n' + p.stdout + p.stderr + '\n')
    p.check_returncode()
    return json.loads(p.stdout) if action in ('status', 'preflight', 'mismatch-refusal') else None

def timed(label, fn, size=0):
    start = time.monotonic()
    result = fn()
    elapsed = time.monotonic() - start
    report['metrics'].append({'operation': label, 'seconds': elapsed, 'bytes': size,
                              'MiB_per_second': size / 1048576 / elapsed if size else None})
    return result

def cli(commands):
    p = subprocess.run(['smbclient', '//' + c['host'] + '/' + c['share'],
                        '-A', str(work / 'smb.auth'), '--client-protection=encrypt',
                        '-m', 'SMB3', '-D', prefix, '-c', commands],
                       capture_output=True, text=True, timeout=180)
    with (work / 'smbclient.log').open('a') as f:
        f.write(commands + '\n' + p.stdout + p.stderr)
    assert p.returncode == 0 and 'NT_STATUS_' not in p.stdout + p.stderr, p.stdout + p.stderr
    return p.stdout

def remote(name):
    raw = s3.get_object(Bucket=bucket, Key=key(name))['Body'].read()
    assert raw.startswith(b'RCLONE\x00\x00'), 'not rclone ciphertext'
    decrypted = reader.read(prefix + '/' + name)
    assert raw != decrypted
    return decrypted

def absent(name):
    try:
        s3.head_object(Bucket=bucket, Key=key(name))
    except ClientError as e:
        if e.response['Error']['Code'] in ('404', 'NoSuchKey'):
            return True
        raise
    return False

def drain():
    start = time.monotonic()
    while time.monotonic() - start < 180:
        h = control('status')
        if (h['process_alive'] and h['mount_ready'] and h['backend_reachable']
                and not any(h[k] for k in ('pending_uploads', 'error_uploads', 'retrying_uploads'))):
            return
        time.sleep(1)
    raise AssertionError('upload drain timeout; preserve dirty cache')

def verify():
    timed('upload-drain', drain)
    for name, data in expected.items():
        assert remote(name) == data, 'independent R2 mismatch: ' + name
    report['checks'].append('raw ciphertext and backup-only independent crypt byte equality after drain')

def put(name, data):
    created.add(name)
    with smb.open_file(path(name), mode='wb') as f:
        f.write(data)
    expected[name] = data

try:
    info = control('preflight')
    assert info['disposable_bucket'] == bucket and info['share_bucket'] == bucket
    assert info['share_subdirectory'] == parent and info['isolated_gateway'] is True
    assert info['disposable_luks_storage'] is True
    assert info['encryption'] == 'rclone-crypt'
    assert info['supported_actions'] and 'mismatch-refusal' in info['supported_actions']
    authorized = True
    report['environment'] = info
    # Listing is read-only. No writes or cleanup on a pre-existing run prefix.
    assert not s3.list_objects_v2(Bucket=bucket, Prefix=reader.key(prefix) + '/', MaxKeys=1).get('Contents')
    smb.register_session(c['host'], username=c['username'], password=c['password'], encrypt=True)
    # Parent must already exist: only create the unique run directory, never shared ancestors.
    smb.mkdir(root)
    guest = subprocess.run(['smbclient', '//' + c['host'] + '/' + c['share'],
                            '-N', '-U', '%', '--client-protection=encrypt', '-m', 'SMB3',
                            '-D', prefix, '-c', 'ls'], capture_output=True, text=True, timeout=60)
    assert any(code in guest.stdout + guest.stderr for code in
               ('NT_STATUS_LOGON_FAILURE', 'NT_STATUS_ACCESS_DENIED')), 'anonymous access not rejected'
    report['checks'].append('anonymous SMB access rejected')
    data = random.Random(42).randbytes(8 * 1048576)
    (work / 'payload').write_bytes(data)
    created.add('file.bin')
    timed('sequential-write-local-acceptance', lambda: cli(f'put {work}/payload file.bin'), len(data))
    expected['file.bin'] = data
    assert 'file.bin' in cli('ls')
    cli(f'get file.bin {work}/readback')
    assert (work / 'readback').read_bytes() == data
    # Python smbclient uses SMB3 over the wire, not a local mounted/cache path.
    with smb.open_file(path('file.bin'), mode='r+b', buffering=0) as f:
        f.seek(1048573)
        assert f.write(b'random-edit') == 11
        f.truncate(2 * 1048576)
        f.flush()
    expected['file.bin'] = (data[:1048573] + b'random-edit' + data[1048584:])[:2 * 1048576]
    cli('rename file.bin renamed.bin; mkdir empty; ls empty; rmdir empty')
    created.remove('file.bin')
    created.add('renamed.bin')
    expected['renamed.bin'] = expected.pop('file.bin')
    put('caf' + chr(233) + '-' + chr(955) + '.txt', b'Unicode filename')
    put('delete-me', b'delete')
    verify()
    cli('del delete-me')
    expected.pop('delete-me')
    drain()
    assert absent('delete-me') and absent('file.bin')
    smb.delete_session(c['host'])
    smb.register_session(c['host'], username=c['username'], password=c['password'], encrypt=True)
    cli(f'get renamed.bin {work}/reconnected')
    assert (work / 'reconnected').read_bytes() == expected['renamed.bin']
    # Separate smbclient process must not bypass the first client's deny-write handle.
    with smb.open_file(path('renamed.bin'), mode='rb', share_access='r'):
        p = subprocess.run(['smbclient', '//' + c['host'] + '/' + c['share'], '-A', str(work / 'smb.auth'),
                            '--client-protection=encrypt', '-m', 'SMB3', '-D', prefix,
                            '-c', f'put {work}/payload renamed.bin'], capture_output=True, text=True, timeout=60)
        assert 'NT_STATUS_SHARING_VIOLATION' in p.stdout + p.stderr
    report['checks'].append('two independent clients: deny-write sharing violation')
    # Seed an unseen object directly in our unique namespace: cold means no VFS data cache.
    created.add('cold.bin')
    reader.run('rcat', 'crypt:' + prefix + '/cold.bin', data=data)
    expected['cold.bin'] = data
    control('refresh')  # refresh directory metadata only; do not prefetch file contents
    for label in ('cold-sequential-read', 'warm-sequential-read'):
        timed(label, lambda: cli(f'get cold.bin {work}/seq'), len(data))
        assert (work / 'seq').read_bytes() == data
    rng = random.Random(7)
    def random_reads():
        with smb.open_file(path('cold.bin'), mode='rb', buffering=0) as f:
            for _ in range(128):
                offset = rng.randrange(len(data) - 4096)
                f.seek(offset)
                assert f.read(4096) == data[offset:offset + 4096]
    timed('warm-random-read-128x4KiB', random_reads, 128 * 4096)
    for i in range(32):
        timed('small-file-close-' + str(i), lambda i=i: put('small-' + str(i), data[:4096]), 4096)
    verify()
    for failure in ('kill-child', 'restart'):
        control('offline')  # only gateway R2 blocked; independent verifier stays online
        assert not control('status')['backend_reachable']
        name = 'pending-' + failure
        created.add(name)
        with smb.open_file(path(name), mode='wb', buffering=0) as f:
            assert f.write(data[:65536]) == 65536
            f.flush()  # explicit SMB FLUSH, not just close/put acknowledgement
            assert absent(name), 'FLUSH unexpectedly uploaded while gateway R2 blocked'
        expected[name] = data[:65536]
        deadline = time.monotonic() + 30
        while not control('status')['pending_uploads']:
            assert time.monotonic() < deadline, 'closed offline write not reported pending'
            time.sleep(1)
        # Hook must attempt changed key/config startup against retained dirty cache,
        # restore original configuration, and report observed refusal, not just exit 0.
        refusal = control('mismatch-refusal')
        assert refusal['key_refused'] and refusal['config_refused']
        assert refusal['dirty_cache_preserved'] and refusal['smb_stopped']
        control(failure)
        if failure == 'kill-child':
            # Probe must fail closed while mount/child is gone, before recovery.
            try:
                smb.stat(path('renamed.bin'))
            except OSError:
                pass
            else:
                raise AssertionError('SMB still serves after child termination')
        control('online')
        control('recover')  # restart unchanged profile/cache; never erase dirty data
        smb.reset_connection_cache()
        smb.register_session(c['host'], username=c['username'], password=c['password'], encrypt=True)
        verify()
    control('pressure-on')  # isolated small cache filesystem only; never fill host disk
    assert control('status')['cache_pressure']
    created.add('pressure.bin')
    try:
        with smb.open_file(path('pressure.bin'), mode='wb') as f:
            for _ in range(16):  # bounded 128MiB; fixture must have <128MiB free
                f.write(data)
            f.flush()
    except OSError as e:
        assert getattr(e, 'errno', None) in (28, 122) or 'DISK_FULL' in str(e), str(e)
        report['checks'].append('disk pressure returns explicit ENOSPC/quota error')
    else:
        raise AssertionError('pressure fixture did not produce fail-safe capacity error')
    control('pressure-off')
    control('online')
    verify()
    reader.rejected_keys(prefix + '/renamed.bin')
    # Restore to a fresh local directory using only the independent backed-up keys.
    restore = work / 'restored'
    assert not restore.exists()
    reader.run('copy', 'crypt:' + prefix, str(restore))
    for name, data in expected.items():
        assert (restore / name).read_bytes() == data
    report['checks'].append('fresh-directory backup-only restore; wrong/missing keys rejected')
    # Delete only tracked names over SMB; never mask failed deletion with raw S3 DELETE.
    for name in sorted(created):
        with contextlib.suppress(FileNotFoundError):
            smb.remove(path(name))
    drain()
    for name in sorted(created):
        # Map exact encrypted names and assert deletion; preserve all evidence on failure.
        assert absent(name)
    smb.rmdir(root)
    report['result'] = 'PASS'
except BaseException as e:
    report['result'] = 'FAIL (objects/cache retained for investigation)'
    report['error'] = type(e).__name__ + ': ' + str(e)
    raise
finally:
    # Restore only the explicitly isolated fault fixture, even on assertion failure.
    for action in (('pressure-off', 'online') if authorized else ()):
        try:
            control(action)
        except Exception as e:
            report.setdefault('restore_errors', []).append(action + ': ' + str(e))
    if report.get('restore_errors'):
        report['result'] = 'FAIL (fault restoration failed; operator intervention required)'
    (work / 'results.json').write_text(json.dumps(report, indent=2))
    (work / 'smb.auth').unlink(missing_ok=True)
    smb.reset_connection_cache()
    print(report['result'], 'report:', work / 'results.json', flush=True)
    if report.get('restore_errors'):
        raise RuntimeError('fault restoration failed; see private report')
PY
