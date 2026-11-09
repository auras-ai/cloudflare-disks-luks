from dataclasses import asdict, dataclass
import ipaddress
import json
from pathlib import Path
import re

from .common import require

GIB = 1024**3
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in
                         ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'])


@dataclass(frozen=True)
class Plan:
    account_id: str
    bucket: str
    interface: str
    address: str
    network: str
    size_gib: int = 16
    cloud_mode: str = 'create'
    location: str = 'auto'
    prefix: str = 'encrypted-files-v1'

    def validate(self):
        require(bool(re.fullmatch('[a-fA-F0-9]{32}', self.account_id)), "Account ID must be 32 hex characters")
        require(bool(re.fullmatch('[a-z0-9][a-z0-9-]{1,61}[a-z0-9]', self.bucket)), "Invalid R2 bucket name")
        require(bool(re.fullmatch('[A-Za-z0-9_.-]{1,15}', self.interface)) and self.interface != 'lo',
                "Select an explicit LAN/VPN interface")
        try:
            address = ipaddress.IPv4Address(self.address)
            network = ipaddress.IPv4Network(self.network, strict=True)
        except ValueError as error:
            raise ValueError('Use a valid IPv4 address and canonical client network CIDR') from error
        require(any(network.subnet_of(n) for n in PRIVATE_NETWORKS) and address in network,
                "The client network must be private LAN/VPN IPv4 and include the gateway")
        require(address not in (network.network_address, network.broadcast_address) or network.prefixlen >= 31,
                "Gateway address must not be a network or broadcast address")
        require(type(self.size_gib) is int and 4 <= self.size_gib <= 4096, "Storage size must be 4–4096 GiB")
        require(self.cloud_mode in ('create', 'manual'), "Choose create or manual Cloudflare setup")
        require(self.location in ('auto', 'apac', 'eeur', 'enam', 'weur', 'wnam', 'oc'), "Invalid R2 location hint")
        require(bool(re.fullmatch('[A-Za-z0-9_-]{1,128}', self.prefix)), "Invalid encrypted prefix")
        return self

    @property
    def endpoint(self):
        return f'https://{self.account_id.lower()}.r2.cloudflarestorage.com'

    @property
    def cache_bytes(self):
        return min(10 * GIB, (self.size_gib - 2) * GIB)

    def json(self):
        return asdict(self)


@dataclass(frozen=True)
class Paths:
    base: Path = Path('/var/lib/cloudflare-disk')
    storage: Path = Path('/srv/r2-disk')
    binary: Path = Path('/usr/local/bin/cloudflare-disk')
    library: Path = Path('/usr/local/lib/cloudflare-disk')
    command: Path = Path('/usr/local/sbin/cloudflare-disk-setup')
    units: Path = Path('/etc/systemd/system')
    udev: Path = Path('/etc/udev/rules.d/99-cloudflare-disk-local.rules')
    mapper: Path = Path('/dev/mapper/r2disk-local')

    @property
    def image(self):
        return self.base / 'local.luks'

    @property
    def ledger(self):
        return self.base / 'setup.json'

    @property
    def state(self):
        return self.storage / 'state'

    @property
    def profile(self):
        return self.state / 'profile.toml'

    @property
    def recovery(self):
        return self.storage / 'recovery'


def profile_text(plan, key_id, paths=Paths()):
    plan.validate()
    require(bool(re.fullmatch('[a-f0-9]{32}', key_id)), "Invalid encryption identity")
    values = dict(bucket=plan.bucket, endpoint=plan.endpoint, state_dir=str(paths.state),
                  cache_dir=str(paths.storage / 'cache'), mount_dir=str(paths.storage / 'mount'),
                  share='cloud', interface=plan.interface, listen_address=plan.address,
                  min_free_bytes=GIB, cache_target_bytes=plan.cache_bytes, writeback_seconds=5, control_port=5572)
    return ''.join(f'{key} = {json.dumps(value)}\n' for key, value in values.items()) + (
        '\n[encryption]\nmode = "rclone-crypt-v1"\n'
        f'prefix = {json.dumps(plan.prefix)}\nkey_id = {json.dumps(key_id)}\n')
