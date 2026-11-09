"""One terminal session: provision, verify, export, and hand off the SMB share."""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import resource
import stat
import sys

from . import credentials, dependencies, firewall, host, recovery, verification
from .common import SetupError, confirm, private_dir, require
from .ledger import Ledger
from .model import Paths, Plan, PRIVATE_NETWORKS
from .storage import Storage


def ask(prompt, default=None):
    value = input(prompt + (f' [{default}]' if default is not None else '') + ': ').strip()
    return value or default or ''


def gather():
    print('Cloudflare disk — client gateway setup\nUse a reserved/static private IPv4 address for this gateway.')
    account = ask('Cloudflare Account ID').lower()
    bucket = ask('Dedicated R2 bucket name')
    mode = ask('Cloudflare setup (create / manual)', 'create')
    from .common import run
    rows = json.loads(run(['ip', '-j', '-4', 'address', 'show']).stdout)
    choices = [(row['ifname'], a['local'], a['prefixlen']) for row in rows for a in row.get('addr_info', [])
               if a.get('family') == 'inet' and 'UP' in row.get('flags', [])
               and any(ipaddress.IPv4Address(a['local']) in network for network in PRIVATE_NETWORKS)]
    require(choices, 'No private IPv4 LAN/VPN interface is up')
    for number, (interface, address, prefix) in enumerate(choices, 1):
        print(f'  {number}. {interface} — {address}/{prefix}')
    selected = int(ask('Interface number', '1')) - 1
    require(0 <= selected < len(choices), 'Choose a displayed interface number')
    interface, address, prefix = choices[selected]
    network = ask('Allowed client IPv4 network (CIDR)', str(ipaddress.ip_network(f'{address}/{prefix}', strict=False)))
    plan = Plan(account_id=account, bucket=bucket, cloud_mode=mode, interface=interface,
                address=address, network=network, size_gib=int(ask('Local encrypted image size in GiB', '16')),
                location=ask('R2 location hint (auto, apac, eeur, enam, weur, wnam, oc)', 'auto') if mode == 'create' else 'auto')
    return plan.validate()


def summary(ledger):
    p = ledger.plan
    print(f'\nGateway ready: smb://{p.address}/cloud\nWindows: \\\\{p.address}\\cloud\n'
          'User: r2disk (the SMB password entered during setup)\n'
          'After reboot: sudo cloudflare-disk-setup unlock\n'
          'Status: sudo cloudflare-disk-setup status\n'
          'Copy the encrypted recovery archive to independent offline storage.\n'
          'Revoke the bootstrap Cloudflare token once setup is complete.')


def install(paths, source, *, resume=False, install_deps=False, import_r2=False):
    if resume:
        require(paths.ledger.is_file(), 'No client setup journal exists; use install on a clean host')
        private_dir(paths.base)
        ledger = Ledger.load(paths.ledger)
    else:
        host.fresh(paths)
        require((source / 'bin/cloudflare-disk').is_file(), 'Use a binary release bundle; build/package sources first')
        if install_deps:
            confirm('Install Ubuntu dependencies and checksum-verified rclone 1.70.3?')
            dependencies.install()
        dependencies.check()
        plan = gather()
        host.network(plan)
        print(f'\nNew {plan.size_gib} GiB image: {paths.image}\nR2: {plan.bucket}/{plan.prefix}\n'
              f'SMB: {plan.address}:445 from {plan.network} on {plan.interface}\n'
              'Creates r2disk, private service state and an SMB-only firewall guard. Manual unlock after reboot.')
        confirm('Create this gateway?', 'create')
        private_dir(paths.base)
        ledger = Ledger.create(paths.ledger, plan)
    if resume and install_deps:
        dependencies.install()
    dependencies.check()
    host.network(ledger.plan)
    storage = Storage(paths, ledger)
    if host.active():
        require(ledger.get('profile_ready') and ledger.get('files_installed') and ledger.get('destination_ready'),
                'An active gateway conflicts with incomplete setup; inspect before resuming')
        require(storage.verify_mount(), 'Encrypted storage is not mounted')
    else:
        print('Preparing recorded encrypted storage…', flush=True)
        storage.provision()
        private_dir(paths.recovery)
        host.account(paths, ledger)
        material = credentials.obtain(paths, ledger, import_r2=import_r2)
        recovery.prepare(paths, ledger, material)
        del material
        if not ledger.get('files_installed'):
            host.install(paths, source)
            ledger.set(files_installed=True)
        print('Verifying encrypted destination…', flush=True)
        host.destination(paths, ledger)
        firewall.configure(paths, ledger)
    host.start(paths, ledger)
    if not ledger.get('verified'):
        print('Testing encrypted SMB and independent R2 readback…', flush=True)
        verification.verify(paths, ledger)
    if not ledger.get('recovery_exported'):
        destination = ask('Encrypted recovery archive output (absolute path)',
                          f'/root/cloudflare-disk-recovery-{ledger.get("install_id")[:8]}.tar.gpg')
        path = recovery.export(paths, ledger, destination)
        print(f'Encrypted recovery archive: {path}')
    ledger.set(complete=True)
    summary(ledger)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Install and operate one encrypted R2/SMB Linux gateway. Credentials are prompted, never flags.')
    parser.add_argument('action', nargs='?', default='install', choices=[
        'install', 'resume', 'check', 'unlock', 'status', 'stop', 'verify', 'export-recovery', 'firewall-apply'])
    parser.add_argument('--install-deps', action='store_true', help='install dependencies on Ubuntu 24.04')
    parser.add_argument('--import-r2', action='store_true', help='resume an ambiguous token create with fresh dashboard S3 credentials')
    parser.add_argument('--output', type=Path, help='new encrypted recovery archive path (export-recovery only)')
    args = parser.parse_args(argv)
    lock = None
    try:
        require(not args.install_deps or args.action in ('install', 'resume'), '--install-deps is for install/resume')
        require(not args.import_r2 or args.action == 'resume', '--import-r2 is for resume')
        require(args.output is None or args.action == 'export-recovery', '--output is for export-recovery')
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.umask(0o077)
        # Ignore inherited rclone configuration, Python module paths and proxy secrets in child tools.
        os.environ.clear()
        os.environ.update(PATH=host.PATH, HOME='/root', LC_ALL='C.UTF-8')
        if args.action == 'check':
            dependencies.check()
            print('Host dependencies available. Installation will also check storage, addresses and ports.')
            return 0
        require(os.geteuid() == 0, 'Run with sudo in a terminal; do not send credentials through chat or command arguments')
        if args.action != 'firewall-apply':
            lock = os.open('/run/cloudflare-disk-setup.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            info = os.fstat(lock)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1,
                    'Unsafe setup lock')
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SetupError('Another setup/lifecycle command is running') from None
        paths = Paths()
        if args.action in ('install', 'resume'):
            install(paths, Path(__file__).resolve().parent.parent, resume=args.action == 'resume',
                    install_deps=args.install_deps, import_r2=args.import_r2)
            return 0
        require(paths.ledger.is_file(), 'No client setup journal exists; use install on a clean host')
        private_dir(paths.base)
        ledger = Ledger.load(paths.ledger)
        storage = Storage(paths, ledger)
        if args.action == 'firewall-apply':
            firewall.apply(ledger)
        elif args.action == 'unlock':
            require(ledger.get('complete'), 'Setup is incomplete; run resume from the release bundle')
            storage.unlock()
            host.start(paths, ledger)
            summary(ledger)
        elif args.action == 'stop':
            host.stop(paths)
            print('Gateway stopped cleanly. Encrypted storage remains mounted; cache retained.')
        else:
            require(storage.verify_mount(), 'Storage is locked; run unlock first')
            if args.action == 'status':
                print(host.as_service(paths, 'status').stdout.decode().strip())
            elif args.action == 'verify':
                require(host.active(), 'Start the gateway before verification')
                print(json.dumps(verification.verify(paths, ledger), indent=2))
            elif args.action == 'export-recovery':
                require(args.output is not None, 'Provide --output /absolute/new-recovery.tar.gpg')
                print('Encrypted recovery archive: ' + str(recovery.export(paths, ledger, args.output)))
        return 0
    except (SetupError, OSError, ValueError, KeyError, TypeError) as error:
        # Arbitrary parser/OS/HTTP diagnostics can contain secrets. Only our curated errors are shown.
        print('Setup stopped: ' + (str(error) if isinstance(error, SetupError) else
                                  'Invalid input or unavailable host resource; recorded progress is retained.'), file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print('\nSetup interrupted; rerun with resume. Recorded storage and keys are retained.', file=sys.stderr)
        return 130
    finally:
        if lock is not None:
            os.close(lock)
