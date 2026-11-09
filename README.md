# Cloudflare Disk

An encrypted network drive backed by Cloudflare R2. One Linux gateway provides
an authenticated SMB3 share to Windows, macOS and Linux clients.

**Version 0.2.0-rc.1 — release candidate.** A guided installer, recovery tools and
release automation are included. The earlier encrypted gateway passed a live
SMB/R2 smoke test; the new installer still needs clean-host and reboot acceptance.
See [release status](docs/RELEASE.md).

## One setup session

Use an existing **Ubuntu Server 24.04 x86_64** gateway with systemd, Python 3.11+,
a static/reserved private IPv4 address and local free space for filesystem metadata,
setup files and the data you actually cache. Setup calculates the metadata/workspace
budget (roughly 0.5 GiB for the default filesystem). The sparse image's 16 GiB
capacity ceiling is not reserved: physical usage grows with written data and
metadata. R2 must be activated in the client's account.

Binary archives and `SHA256SUMS` will be published on the
[Releases page](https://github.com/auras-ai/cloudflare-disks-luks/releases).
Until the first tagged release, [build the candidate from source](docs/RELEASE.md).
With a binary archive, verify its checksum, extract it, and run:

```sh
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf cloudflare-disk-0.2.0-rc.1-linux-x86_64-gnu.tar.gz
cd cloudflare-disk-0.2.0-rc.1-linux-x86_64-gnu
sudo ./setup install --install-deps
```

The terminal session collects the account, bucket, LAN/VPN network and passwords.
It creates the private bucket and bucket-scoped R2 credential (or imports an
existing credential), creates sparse LUKS2 storage, generates file-encryption
keys, installs the dedicated service and firewall guard, tests encrypted SMB and an
independent R2 decrypt, and exports an encrypted recovery archive.

- **Client-session checklist:** [docs/CLIENT-SETUP.md](docs/CLIENT-SETUP.md)
- **Day-to-day operations and recovery:** [docs/OPERATIONS.md](docs/OPERATIONS.md)
- **Build, verification and publishing:** [docs/RELEASE.md](docs/RELEASE.md)

Interrupted setup resumes with `sudo ./setup resume`. Storage identity and keys
are retained; ambiguous formatting/token creation stops for inspection.

## Client connection

The installer prints the actual gateway address. Use **r2disk** and the SMB
password entered during setup:

- Windows Explorer → Map network drive → `\\GATEWAY-IP\cloud`
- macOS Finder → Go → Connect to Server → `smb://GATEWAY-IP/cloud`
- Linux file manager → `smb://GATEWAY-IP/cloud`

After a gateway reboot, run `sudo cloudflare-disk-setup unlock` and enter the
LUKS passphrase. The gateway remains locked until this manual step.

## What is encrypted

| Layer | Protection |
| --- | --- |
| Client ↔ gateway | Required authenticated SMB3 encryption |
| Local image | LUKS2: cache, keys, Samba database and temporary state |
| R2 objects | rclone crypt: file contents, filenames and directory names |
| Recovery export | Passphrase-encrypted GPG archive, verified after creation |

R2 stores encrypted files, not a mounted LUKS image. Object sizes, counts and
access patterns remain visible. An unlocked gateway/root or an authenticated
client can access plaintext. Keep swap/hibernation encrypted or disabled.

Local storage grows with cached data plus filesystem/encryption overhead. Discard
passthrough and ext4 discard-on-free reclaim deleted cache blocks automatically;
setup/unlock also trim free space. See
[local disk usage](docs/OPERATIONS.md#local-disk-usage).

## Operational boundaries

Use one gateway and one dedicated prefix, with all writers using its SMB share.
This is intended for documents and media, not databases, VM disks, multi-gateway
writes or full POSIX/NTFS semantics. SMB save acknowledgement is local acceptance;
upload completion requires clean telemetry and important data should be verified
independently. Keep independent file backups and an offline recovery-key copy.

SMB is bound to the chosen private address. The installer adds a dedicated
TCP 445 guard and a narrow UFW allow rule when UFW is already active; other host
firewall policies still apply. Remote clients need an existing VPN.

## Source and license

The source archive includes locked Rust dependencies, Python installer tests and
CI workflows. Runtime tools are installed separately; see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

Source repository: [auras-ai/cloudflare-disks-luks](https://github.com/auras-ai/cloudflare-disks-luks).
Project license selection is pending. Release-archive publishing requires a chosen
`LICENSE` and Cargo SPDX license identifier. See [LICENSE-PENDING.md](LICENSE-PENDING.md).
