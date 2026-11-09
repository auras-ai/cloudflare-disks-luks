"""A dedicated SMB-only nftables guard; existing host tables remain authoritative."""
from pathlib import Path
import shutil

from .common import install_same, require, run

TABLE = 'cloudflare_disk_smb'


def rules(plan):
    plan.validate()
    return f'''table inet {TABLE} {{
  chain input {{
    type filter hook input priority -10; policy accept;
    iifname "{plan.interface}" ip saddr {plan.network} ip daddr {plan.address} tcp dport 445 accept
    iifname "lo" ip saddr {plan.address} ip daddr {plan.address} tcp dport 445 accept
    tcp dport 445 drop
  }}
}}
'''


def exists():
    return run(['nft', 'list', 'table', 'inet', TABLE], check=False).returncode == 0


def apply(ledger):
    require(ledger.get('firewall_owned'), 'Firewall table was not reserved by this installation')
    text = (f'delete table inet {TABLE}\n' if exists() else '') + rules(ledger.plan)
    run(['nft', '-c', '-f', '-'], data=text.encode())
    run(['nft', '-f', '-'], data=text.encode())


def configure(paths, ledger):
    if not ledger.get('firewall_owned'):
        require(not exists(), 'A cloudflare_disk_smb table already exists; inspect before setup')
        ledger.set(firewall_owned=True)
    if shutil.which('ufw') and b'Status: active' in run(['ufw', 'status']).stdout:
        # Back up settings before adding the narrow allow rule, without enabling UFW.
        for name in ('user.rules', 'user6.rules'):
            original = Path('/etc/ufw') / name
            backup = paths.base / ('before-ufw-' + name)
            if original.exists() and not backup.exists():
                install_same(backup, original.read_bytes())
        p = ledger.plan
        run(['ufw', 'allow', 'in', 'on', p.interface, 'proto', 'tcp', 'from', p.network,
             'to', p.address, 'port', '445', 'comment', 'cloudflare-disk SMB'])
    apply(ledger)
