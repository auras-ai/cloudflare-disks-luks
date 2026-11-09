# Gateway operations

## Runtime and dependencies

Binary candidate: Linux x86_64, glibc **2.36+**. Recommended gateway: Ubuntu
Server 24.04 (glibc 2.39). Python **3.11+**, systemd, cryptsetup with LUKS2,
e2fsprogs, util-linux, iproute2, udev, nftables, GnuPG, rclone **1.70+**, Samba
**4.19+** (`smbd`, `testparm`, `pdbedit`, `smbclient`), FUSE3 **3.14+** and working
`/dev/fuse` access for the service account are required.

`setup install --install-deps` installs Ubuntu packages and prevents package
scripts from starting an unconfigured Samba. Only newly installed distro Samba
units are disabled. An existing package-start policy is respected by refusing
automatic installation. Package logs remain suppressed from setup errors.

Ubuntu's older rclone package is insufficient. The installer downloads **1.70.3**
from upstream, falling back to GitHub, and verifies the pinned SHA-256:
`7d69057e69385f6514a9684c7eaa424d972096b130284bb34dd967c4ed4f9dad`.
It does not replace an existing `/usr/local/bin/rclone`. Operators can install
a verified newer rclone before setup. `setup check` checks dependency versions;
the supervisor also verifies the running rclone control API at startup.

Do not run package setup on a machine already serving Samba. Existing AppArmor,
SELinux and firewall policies may need scoped administrator changes; do not
disable them globally. Reserve the configured IPv4 address through DHCP or static
configuration before setup; networking configuration is not changed by the installer.

## Commands

```sh
sudo cloudflare-disk-setup status
sudo cloudflare-disk-setup verify       # small SMB/R2 write/read/delete test
sudo cloudflare-disk-setup stop         # stop writers and drain; retain storage
sudo cloudflare-disk-setup unlock       # unlock/mount if necessary, then start
sudo cloudflare-disk-setup export-recovery --output /absolute/new-recovery.tar.gpg
sudo journalctl -u cloudflare-disk.service -n 100 --no-pager
```

`stop` leaves the encrypted filesystem mounted for inspection. A successful stop
means the supervisor completed its local drain procedure; it is not a backup.
`unlock` never formats storage, generates keys or initializes a destination.
Do not enable the gateway at boot before unlocking. After reboot, enter the LUKS
passphrase with `unlock` and wait for readiness before reconnecting clients.

Status reports `process_alive`, `mount_ready`, `backend_reachable`, `cache_pressure`,
`pending_uploads`, `error_uploads`, `retrying_uploads`, `transfer_errors`, `in_use`,
`cache_bytes` and `available_bytes`. For important files, close writers, wait for
zero queued/error/retrying transfers, then verify their bytes independently in R2.

## Installed layout

| Location | Purpose |
| --- | --- |
| `/var/lib/cloudflare-disk/setup.json` | Root-only, nonsecret progress and storage identity |
| `/var/lib/cloudflare-disk/local.luks` | Preallocated, root-only LUKS2 image |
| `/srv/r2-disk/state` | Private profile, keys, Samba and control state |
| `/srv/r2-disk/cache` | Persistent full VFS cache; may contain pending writes |
| `/srv/r2-disk/mount` | Decrypted FUSE mount, sealed when the gateway is running |
| `/srv/r2-disk/recovery` | Root-only key/header backups and acceptance evidence |
| `/usr/local/bin/cloudflare-disk` | Rust supervisor |
| `/usr/local/lib/cloudflare-disk/installer` | Installed Python lifecycle modules |
| `/usr/local/sbin/cloudflare-disk-setup` | Installed operator command |
| `/etc/udev/rules.d/99-cloudflare-disk-local.rules` | Volume-specific desktop auto-unlock exclusion |
| `/etc/systemd/system/cloudflare-disk*` | Service, firewall unit and client drop-in |
| `/etc/systemd/system/srv-r2\x2ddisk.mount` | Manual-unlock mount dependency |

The bare `/srv/r2-disk` underlay is root-owned 0700. Its mounted filesystem root
is 0755; protected children are 0700 and secrets are 0600. The supervisor, rclone
and smbd run as `r2disk` with systemd's inherited `CAP_NET_BIND_SERVICE`. They are
not strongly sandboxed from each other. Root and that UID are trusted.

## Firewall

The dedicated `inet cloudflare_disk_smb` table affects TCP 445 only: it allows
the selected interface, private source subnet and destination address, plus a
same-host verification connection; other TCP 445 traffic, including IPv6, drops.
Samba additionally binds only the selected IPv4 `/32`. The control API is
authenticated and loopback-only at 127.0.0.1:5572.

The guard runs before service startup and is reapplied by `unlock`. It never
flushes other tables. If UFW is active, setup backs up its user rules under the
private setup directory and adds a narrow allow rule. UFW is not enabled by setup.
Other firewall chains can still reject clients: add the same narrow allow under
their policy when needed. A firewall reload that flushes all tables requires
`sudo cloudflare-disk-setup firewall-apply` to restore the guard. Do not forward
TCP 445 from a public network. Off-site access uses an existing VPN.

## Interruption and failure recovery

Never delete the image, dirty cache, `recovery.json`, crypt password/salt or profile
to fix a startup error. Never rerun `init` on an existing installation.

- **Missing/wrong mount or UUID:** inspect `lsblk`, `losetup --associated`,
  `cryptsetup status r2disk-local` and the saved journal. Restore the original
  image/identity. The installer refuses uncertain or foreign storage.
- **Another desktop mapping:** the volume-specific udev rule prevents new races.
  If one already exists, verify its underlying image and LUKS UUID, ensure it has
  no mounts/users and have the administrator close or deliberately rename it.
  Do not close unrelated root-volume mappings.
- **Sealed mount after crash:** stop the gateway, inspect its cgroup and stale
  Samba/rclone processes, unmount only the stale FUSE mount normally, verify the
  encrypted parent remains mounted, then restore the empty underlying mount
  directory to `r2disk:r2disk`, mode 0700. Preserve state/cache and start with the
  same profile. No automatic force-unmount or cache deletion is provided.
- **Network outage or full cache:** stop client writes, preserve the image and
  restore connectivity/free space outside dirty cache. Soft rclone limits cannot
  evict dirty files. Inspect all health counters after reconnecting.
- **Unclean stop:** keep storage unlocked for investigation. The supervisor retains
  cache and recovery state; command errors do not mean pending data is uploaded.

The header is formatted at most once per recorded intent. Interrupted LUKS/mkfs
without a verifiable recorded identity requires manual inspection of a clone.
No resume path reformats ambiguous storage. Root-only journal edits should be
made only after independently establishing the exact device/image state.

## Offline recovery archive

The exported `.tar.gpg` is encrypted with a separate passphrase using GnuPG's
integrity-protected AES256 symmetric format. Setup decrypts and byte-checks the
archive before writing the final export. Exported archives contain the profile,
S3/SMB/crypt credentials, LUKS header, volume UUIDs and setup metadata. The LUKS
passphrase and client file contents are not included.

Copy the encrypted archive off the gateway; keep its passphrase separately. To
inspect on an isolated machine, decrypt onto encrypted storage:

```sh
umask 077
mkdir /encrypted/recovery
gpg --output /encrypted/recovery/recovery.tar --decrypt /offline/recovery.tar.gpg
tar -xf /encrypted/recovery/recovery.tar -C /encrypted/recovery
```

For uploaded-file recovery, configure an isolated rclone S3 remote with the
saved endpoint, bucket-scoped key/secret, `provider = Cloudflare`, `region = auto`
and `no_check_bucket = true`. Configure a crypt remote pointing at the saved
bucket/prefix, using **both** saved crypt values, `filename_encryption = standard`
and `directory_name_encryption = true`. Use interactive `rclone config` on the
encrypted recovery disk; do not put values in command arguments. `obscure` is
reversible and does not protect a configuration file. Read/copy to a new recovery
directory with a fresh cache and compare bytes; never sync/delete the source.

Local pending writes require the original LUKS image and working unlock access.
A header backup alone contains no client data. Restore/test a header only on a
disposable image clone with the recorded UUID and passphrase. If the original
image is gone, only successfully uploaded objects can be recovered from R2.

## Credential rotation and upgrades

R2 access credentials can be replaced while stopped without changing crypt keys,
profile identity or cache paths. Update both encrypted operational and recovery
copies consistently, verify destination/readback, and make a new recovery export
before revoking the old token. Python setup's recovery `material.json` must also
stay consistent if setup may be resumed. SMB rotation similarly updates its saved
password; the private Samba database is provisioned on each service start.

Crypt-key rotation is a new-prefix migration and full copy, not editing a password
in place. LUKS passphrase rotation uses cryptsetup and a new header backup; older
headers can retain access with old passphrases.

This candidate installs fresh hosts; it does not auto-upgrade or adopt legacy
deployments. For a future upgrade: verify release checksums, complete clean drain,
back up the installed binary/unit/modules and encrypted recovery material, test
the new release on a clone, then replace executable code only. Preserve storage,
keys, paths and custom firewall settings. Roll back executable code from the
backup if needed; do not roll back or discard newly accepted data.

## Retiring a gateway

Stop new writes, drain, independently verify/copy all required data, and keep the
original image plus recovery archive until retention is agreed. Disable/stop
the units, unmount the FUSE/storage mounts normally, close only the recorded
mapping and detach its loop. Remove only the installation's own files and firewall
rule/table after inspecting them. Revoke the bucket token when no longer needed.
No destructive uninstall command or automatic bucket deletion is provided.
