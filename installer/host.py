"""Install this release's files and narrowly scoped service integration."""
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import stat
import time

from . import firewall
from .common import install_same, no_symlinks, private_dir, require, run

SERVICE = 'cloudflare-disk.service'
MOUNT_UNIT = r'srv-r2\x2ddisk.mount'
MODULES = ('__init__', 'cli', 'common', 'model', 'cloudflare', 'ledger', 'storage',
           'credentials', 'dependencies', 'firewall', 'host', 'verification', 'recovery')
PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'


def active():
    return run(['systemctl', 'is-active', '--quiet', SERVICE], check=False).returncode == 0


def network(plan):
    rows = json.loads(run(['ip', '-j', '-4', 'address', 'show', 'dev', plan.interface]).stdout)
    require(any('UP' in row.get('flags', []) and any(a.get('local') == plan.address
                for a in row.get('addr_info', [])) for row in rows),
            'The selected private IPv4 address must be assigned to an up LAN/VPN interface')


def fresh(paths):
    for path in (paths.base, paths.storage, paths.mapper, paths.binary, paths.library, paths.command,
                 paths.udev, paths.units / SERVICE, paths.units / MOUNT_UNIT,
                 paths.units / 'cloudflare-disk-firewall.service', paths.units / (SERVICE + '.d')):
        require(not path.exists() and not path.is_symlink(), f'Existing installation/path: {path}; use resume only for a recorded client setup')
    try:
        pwd.getpwnam('r2disk')
    except KeyError:
        pass
    else:
        require(False, 'The r2disk user already exists; use a clean gateway host')
    for port in (445, 5572):
        with socket.socket() as probe:
            try:
                probe.bind(('0.0.0.0', port))
            except OSError:
                require(False, f'TCP {port} is in use; choose a dedicated gateway, do not replace host services')


def account(paths, ledger):
    try:
        user = pwd.getpwnam('r2disk')
        require(ledger.get('user_requested'), 'Unrecorded r2disk account; inspect manually')
    except KeyError:
        require(not ledger.get('service_uid'), 'The recorded r2disk account is missing')
        ledger.set(user_requested=True)
        shell = shutil.which('nologin')
        require(shell is not None, 'Install nologin before account provisioning')
        run(['useradd', '--system', '--user-group', '--home-dir', paths.state,
             '--no-create-home', '--shell', shell, 'r2disk'])
        user = pwd.getpwnam('r2disk')
    require(user.pw_uid != 0 and user.pw_gid != 0 and user.pw_dir == str(paths.state)
            and Path(user.pw_shell).name == 'nologin', 'r2disk account does not match this installation')
    require(ledger.get('service_uid', user.pw_uid) == user.pw_uid
            and ledger.get('service_gid', user.pw_gid) == user.pw_gid, 'Service account IDs changed')
    ledger.set(service_uid=user.pw_uid, service_gid=user.pw_gid)
    for path in (paths.state, paths.storage / 'cache', paths.storage / 'mount', paths.state / 'tmp'):
        private_dir(path, uid=user.pw_uid, gid=user.pw_gid)
    return user


def public_dir(path):
    path = no_symlinks(path)
    if not path.exists():
        path.mkdir(mode=0o755)
        os.chmod(path, 0o755)
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'Installation directory must be root-owned and not writable by others')


def install(paths, source):
    binary = source / 'bin/cloudflare-disk'
    require(binary.is_file() and not binary.is_symlink(), 'Use a binary release bundle (bin/cloudflare-disk is missing)')
    install_same(paths.binary, binary.read_bytes(), mode=0o755)
    public_dir(paths.library)
    public_dir(paths.library / 'installer')
    for module in MODULES:
        install_same(paths.library / 'installer' / (module + '.py'),
                     (source / 'installer' / (module + '.py')).read_bytes(), mode=0o644)
    launcher = ('#!/usr/bin/python3\nimport sys\nsys.dont_write_bytecode = True\n'
                f'sys.path.insert(0, {str(paths.library)!r})\n'
                'from installer.cli import main\nraise SystemExit(main())\n')
    install_same(paths.command, launcher, mode=0o755)
    install_same(paths.units / MOUNT_UNIT,
                 '[Unit]\nDescription=Encrypted Cloudflare disk storage (manual unlock)\n\n'
                 f'[Mount]\nWhat={paths.mapper}\nWhere={paths.storage}\nType=ext4\nOptions=nodev,nosuid\n', mode=0o644)
    install_same(paths.units / SERVICE, (source / 'packaging/cloudflare-disk.service').read_bytes(), mode=0o644)
    public_dir(paths.units / (SERVICE + '.d'))
    install_same(paths.units / (SERVICE + '.d/10-client.conf'),
                 '[Unit]\nRequires=cloudflare-disk-firewall.service\nAfter=cloudflare-disk-firewall.service\n\n'
                 f'[Service]\nExecStartPre=+{paths.command} firewall-apply\n', mode=0o644)
    install_same(paths.units / 'cloudflare-disk-firewall.service',
                 '[Unit]\nDescription=Private LAN/VPN SMB firewall guard\nAfter=nftables.service ufw.service\n'
                 f'Before={SERVICE}\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\n'
                 f'ExecStart={paths.command} firewall-apply\n', mode=0o644)
    run(['systemd-analyze', 'verify', paths.units / SERVICE, paths.units / MOUNT_UNIT,
         paths.units / 'cloudflare-disk-firewall.service'])
    run(['systemctl', 'daemon-reload'])


def as_service(paths, action, *, check=True, timeout=120):
    return run(['runuser', '-u', 'r2disk', '--', 'env', '-i', f'PATH={PATH}',
                f'HOME={paths.state}', f'TMPDIR={paths.state / "tmp"}', paths.binary,
                action, '--config', paths.profile], check=check, timeout=timeout)


def destination(paths, ledger):
    require(not active(), 'Destination verification requires a stopped gateway')
    verified = as_service(paths, 'verify-destination', check=False)
    if verified.returncode:
        require(not ledger.get('destination_ready'), 'Existing remote identity could not be verified; check connectivity and saved keys')
        # Rust refuses every nonempty prefix: this is safe after a lost response.
        as_service(paths, 'initialize-destination')
    ledger.set(destination_ready=True)


def start(paths, ledger):
    network(ledger.plan)
    firewall.apply(ledger)
    if not active():
        run(['systemd-run', '--wait', '--pipe', '--collect', '--unit=cloudflare-disk-doctor',
             '--property=User=r2disk', '--property=Group=r2disk',
             '--property=AmbientCapabilities=CAP_NET_BIND_SERVICE', f'--property=Environment=PATH={PATH}',
             paths.binary, 'doctor', '--config', paths.profile])
        if run(['systemctl', 'is-failed', '--quiet', SERVICE], check=False).returncode == 0:
            run(['systemctl', 'reset-failed', SERVICE])
        run(['systemctl', 'start', SERVICE])
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        result = as_service(paths, 'status', check=False, timeout=20)
        if result.returncode == 0:
            value = json.loads(result.stdout)
            if all(value.get(k) for k in ('process_alive', 'mount_ready', 'backend_reachable')):
                return value
        time.sleep(1)
    require(False, 'Gateway did not become ready; inspect journalctl -u cloudflare-disk (cache and keys retained)')


def stop(paths):
    run(['systemctl', 'stop', SERVICE], timeout=180)
    result = run(['systemctl', 'show', SERVICE, '--property=Result', '--value']).stdout.strip()
    require(result == b'success', 'Gateway shutdown was not clean; keep storage unlocked and retain cache for recovery')
    require(not active(), 'Gateway is still active')
