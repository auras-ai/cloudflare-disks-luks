use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    process::Command,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Versioned, immutable crypt settings: standard filenames and encrypted directories.
/// key_id is a nonsecret operator-assigned identity, never a password or key hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptConfig {
    mode: CryptMode,
    prefix: String,
    key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptMode {
    #[serde(rename = "rclone-crypt-v1")]
    RcloneCryptV1,
}

impl CryptConfig {
    pub const REMOTE: &'static str = "crypt:";
    pub const FILENAME_ENCRYPTION: &'static str = "standard";
    pub const DIRECTORY_ENCRYPTION: &'static str = "true";

    pub fn underlying_remote(&self, bucket: &str) -> String {
        format!("r2:{bucket}/{}", self.prefix)
    }

    /// Nonsecret destination identity; authenticated by reading it through crypt.
    pub fn identity(&self, profile: &Profile) -> String {
        serde_json::json!({"version": 1, "endpoint": profile.endpoint,
            "remote": self.underlying_remote(&profile.bucket), "crypt": self,
            "filename_encryption": Self::FILENAME_ENCRYPTION,
            "directory_name_encryption": Self::DIRECTORY_ENCRYPTION})
        .to_string()
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            !self.prefix.is_empty() && self.prefix.len() <= 128
                && self.prefix.split('/').all(|part| !part.is_empty()
                    && part != "." && part != ".."
                    && part.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))),
            "crypt prefix must be a dedicated relative path of 1–128 ASCII letters, digits, hyphens or underscores separated by single slashes"
        );
        ensure!(self.key_id.len() == 32 && self.key_id.bytes().all(|b| b.is_ascii_hexdigit()),
            "crypt key_id must be a nonsecret 32-hex identity; keep it unchanged with the crypt keys and destination");
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Missing encryption means legacy plaintext, never an encrypted default.
    #[serde(default)]
    pub encryption: Option<CryptConfig>,
    pub bucket: String,
    pub endpoint: String,
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub mount_dir: PathBuf,
    pub share: String,
    pub interface: String,
    /// Pin SMB to one private IPv4 address instead of every address on an interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_address: Option<Ipv4Addr>,
    pub min_free_bytes: u64,
    pub cache_target_bytes: u64,
    pub writeback_seconds: u64,
    pub control_port: u16,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Secrets {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub smb_password: String,
    pub crypt_password: String,
    pub crypt_salt: String,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secrets([REDACTED])")
    }
}

impl Secrets {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.access_key_id.len() == 32
                && self.access_key_id.bytes().all(|c| c.is_ascii_hexdigit()),
            "R2 access key must be 32 hexadecimal characters"
        );
        ensure!(
            self.secret_access_key.len() == 64
                && self
                    .secret_access_key
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit()),
            "R2 secret must be 64 hexadecimal characters"
        );
        ensure!(
            (12..=128).contains(&self.smb_password.len())
                && !self.smb_password.chars().any(char::is_control),
            "SMB password must be 12–128 bytes without control characters"
        );
        for (name, value) in [
            ("crypt password", &self.crypt_password),
            ("crypt salt", &self.crypt_salt),
        ] {
            ensure!(
                (16..=1024).contains(&value.len()) && !value.chars().any(char::is_control),
                "{name} must be 16–1024 bytes without control characters"
            );
        }
        Ok(())
    }

    pub fn from_protected_file(path: &Path) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .context("open protected secret input")?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_file()
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.mode() & 0o777 == 0o600
                && meta.nlink() == 1,
            "secret input must be an owned, single-link regular 0600 file"
        );
        let mut text = Zeroizing::new(String::new());
        (&mut file)
            .take(16_385)
            .read_to_string(&mut text)
            .context("read secret input")?;
        ensure!(text.len() <= 16_384, "secret input too large");
        let secrets: Self = toml::from_str(&text)
            .map_err(|_| anyhow::anyhow!("invalid secret input TOML (details redacted)"))?;
        secrets.validate()?;
        Ok(secrets)
    }
}

impl Profile {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path).context("read profile")?;
        let profile: Self = toml::from_str(&text)
            .map_err(|_| anyhow::anyhow!("invalid profile TOML (details redacted)"))?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<()> {
        self.encryption.as_ref().context(
            "legacy plaintext profile refused: stop writers, drain and verify old data, then copy through crypt into a NEW dedicated prefix with backed-up keys; verify decrypted data before switching, retain the source for rollback; never relabel the old profile"
        )?.validate()?;
        let bucket = self.bucket.as_bytes();
        ensure!(
            (3..=63).contains(&bucket.len())
                && bucket.first().is_some_and(u8::is_ascii_alphanumeric)
                && bucket.last().is_some_and(u8::is_ascii_alphanumeric)
                && bucket
                    .iter()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-'),
            "bucket must be a 3–63 character lowercase R2 bucket name"
        );
        let account = self
            .endpoint
            .strip_prefix("https://")
            .and_then(|s| s.strip_suffix(".r2.cloudflarestorage.com"));
        ensure!(account.is_some_and(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())), "endpoint must be https://<32-hex-account-id>.r2.cloudflarestorage.com (no path, port or credentials)");
        ensure!(
            !self.share.is_empty()
                && self.share.len() <= 64
                && self
                    .share
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                && !["global", "homes", "printers", "ipc$"]
                    .contains(&self.share.to_ascii_lowercase().as_str()),
            "invalid or reserved share name"
        );
        ensure!(
            !self.interface.is_empty()
                && self.interface.len() < libc::IFNAMSIZ
                && self.interface != "lo"
                && self
                    .interface
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)),
            "select one explicit LAN/VPN interface, not loopback or a wildcard"
        );
        if let Some(address) = self.listen_address {
            let octets = address.octets();
            ensure!(
                address.is_private() || (octets[0] == 100 && (64..=127).contains(&octets[1])),
                "SMB listen address must be private LAN or shared-address VPN IPv4"
            );
        }
        let paths = [&self.state_dir, &self.cache_dir, &self.mount_dir];
        for path in paths {
            ensure!(
                path.is_absolute()
                    && path != Path::new("/")
                    && path
                        .components()
                        .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
                    && path
                        .to_str()
                        .is_some_and(|s| !s.chars().any(char::is_control)
                            && !s.contains(['\\', '"', '%', ';', '[', ']'])),
                "paths must be absolute, normalized and safe for service configuration"
            );
            // Reject aliases and symlinks before any creation; secure_directory also checks at open time.
            let mut prefix = PathBuf::new();
            for part in path.components() {
                prefix.push(part);
                match fs::symlink_metadata(&prefix) {
                    Ok(m) => ensure!(
                        m.is_dir() && !m.file_type().is_symlink(),
                        "path contains a symlink or non-directory"
                    ),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                    Err(e) => return Err(e.into()),
                }
            }
        }
        for (i, left) in paths.iter().enumerate() {
            for right in &paths[i + 1..] {
                ensure!(
                    !left.starts_with(right) && !right.starts_with(left),
                    "state/cache/mount paths must not overlap"
                );
            }
        }
        ensure!(
            self.min_free_bytes >= 64 * 1024 * 1024
                && self.cache_target_bytes >= self.min_free_bytes,
            "cache target must cover minimum free space (at least 64 MiB)"
        );
        ensure!(
            (1..=3600).contains(&self.writeback_seconds) && self.control_port >= 1024,
            "invalid writeback delay or control port"
        );
        Ok(())
    }
}

/// Kernel mount identity, retained and compared throughout the serving lifetime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageIdentity(pub String);

pub trait StorageProbe {
    fn inspect(&self, root: &Path) -> Result<StorageIdentity>;

    fn reject_nested_mounts(&self, _paths: &[&Path]) -> Result<()> {
        Ok(())
    }
}

pub struct LinuxStorage;
impl StorageProbe for LinuxStorage {
    fn reject_nested_mounts(&self, paths: &[&Path]) -> Result<()> {
        reject_nested_mounts(paths, &fs::read_to_string("/proc/self/mountinfo")?)
    }

    fn inspect(&self, root: &Path) -> Result<StorageIdentity> {
        let mounts = fs::read_to_string("/proc/self/mountinfo")?;
        let identity = inspect_mountinfo(root, &mounts, Path::new("/sys/dev/block"))?;
        let dev = fs::metadata(root)?.dev();
        let parts: Vec<_> = identity.0.split(':').collect();
        ensure!(
            parts[1] == libc::major(dev).to_string() && parts[2] == libc::minor(dev).to_string(),
            "storage mount changed during probe"
        );
        Ok(identity)
    }
}

/// No environment assertion, device access, cryptsetup invocation or privilege escalation.
/// Unknown sysfs topology (including restricted container namespaces) is a hard error.
pub fn inspect_mountinfo(root: &Path, mounts: &str, sysfs: &Path) -> Result<StorageIdentity> {
    let rows: Vec<_> = mounts
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields.len() > 6 && fields[4] == root.to_str().unwrap_or("")).then_some(fields)
        })
        .collect();
    ensure!(rows.len() == 1, "encrypted storage mount absent or ambiguous; administrator must mount an unlocked LUKS2 filesystem; use host deployment if Docker cannot prove provenance");
    let row = &rows[0];
    ensure!(
        row[3] == "/" && row[5].split(',').any(|v| v == "rw"),
        "storage must expose the whole writable encrypted filesystem, not a subdirectory bind"
    );
    ensure!(
        row[2].split(':').count() == 2 && row[2].bytes().all(|b| b.is_ascii_digit() || b == b':'),
        "invalid mount device"
    );
    fn ancestry(device: &Path, depth: usize) -> Result<String> {
        ensure!(depth < 16, "unknown block ancestry");
        if let Ok(uuid) = fs::read_to_string(device.join("dm/uuid")) {
            if uuid.trim().starts_with("CRYPT-LUKS2-") {
                return Ok(uuid.trim().to_owned());
            }
        }
        let slaves = fs::read_dir(device.join("slaves"))
            .context("cannot prove LUKS2 ancestry; use host deployment with readable sysfs")?;
        let mut identities = Vec::new();
        for slave in slaves {
            identities.push(ancestry(&slave?.path(), depth + 1)?);
        }
        ensure!(!identities.is_empty(), "unencrypted or unknown backing refused; administrator must provision and unlock LUKS2 outside the service");
        identities.sort();
        Ok(identities.join(","))
    }
    let crypt = ancestry(&sysfs.join(row[2]), 0)?;
    Ok(StorageIdentity(format!("{}:{}:{crypt}", row[0], row[2])))
}

/// Reject every mount at or beneath protected paths, including same-device binds.
/// Decode mountinfo escapes before component-aware comparison (not string prefixes).
pub fn reject_nested_mounts(paths: &[&Path], mounts: &str) -> Result<()> {
    for line in mounts.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        ensure!(fields.len() > 6, "invalid mountinfo row");
        let mount = fields[4]
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\");
        ensure!(
            !paths.iter().any(|path| Path::new(&mount).starts_with(path)),
            "nested mount in protected state/cache storage refused"
        );
    }
    Ok(())
}

pub fn validate_storage(profile: &Profile, probe: &impl StorageProbe) -> Result<StorageIdentity> {
    let root = profile.state_dir.parent().context("missing storage root")?;
    ensure!(
        root != Path::new("/") && profile.cache_dir.parent() == Some(root),
        "state and cache must be private siblings on one LUKS2 mount"
    );
    let identity = probe.inspect(root)?;
    probe.reject_nested_mounts(&[&profile.state_dir, &profile.cache_dir])?;
    // Also detect device changes between the mountinfo snapshot and metadata reads.
    for path in [&profile.state_dir, &profile.cache_dir] {
        if path.exists() {
            ensure!(
                fs::metadata(path)?.dev() == fs::metadata(root)?.dev(),
                "storage sibling is on a different filesystem"
            );
        }
    }
    Ok(identity)
}

/// Walk via directory descriptors: never follow symlinks or chmod existing host directories.
fn secure_directory(path: &Path, create: bool) -> Result<File> {
    let mut dir = File::open("/")?;
    let parts: Vec<_> = path
        .components()
        .filter_map(|c| {
            if let Component::Normal(p) = c {
                Some(p)
            } else {
                None
            }
        })
        .collect();
    for (index, part) in parts.iter().enumerate() {
        use std::os::unix::ffi::OsStrExt;
        let name = CString::new(part.as_bytes())?;
        if create {
            let result = unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) };
            if result < 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        ensure!(
            fd >= 0,
            "cannot securely open profile directory: {}",
            std::io::Error::last_os_error()
        );
        dir = unsafe { File::from_raw_fd(fd) };
        let meta = dir.metadata()?;
        let uid = unsafe { libc::geteuid() };
        ensure!(
            meta.uid() == 0 || meta.uid() == uid,
            "directory ancestor has an untrusted owner"
        );
        ensure!(
            meta.mode() & 0o022 == 0 || (meta.uid() == 0 && meta.mode() & libc::S_ISVTX != 0),
            "directory ancestor is writable by others"
        );
        if index == parts.len() - 1 {
            ensure!(
                meta.uid() == uid && meta.mode() & 0o777 == 0o700,
                "profile directories must be owned by current user and mode 0700"
            );
        }
    }
    Ok(dir)
}

fn pinned_path(dir: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()))
}

fn atomic_write(dir: &File, name: &str, contents: &[u8]) -> Result<()> {
    let parent = pinned_path(dir);
    let mut temp = tempfile::NamedTempFile::new_in(&parent)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temp.write_all(contents)?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(parent.join(name))
        .map_err(|_| anyhow::anyhow!("refusing to overwrite existing profile or secret file"))?;
    dir.sync_all()?;
    Ok(())
}

pub fn initialize(profile: &Profile, secrets: &Secrets) -> Result<()> {
    initialize_with_storage(profile, secrets, &LinuxStorage)
}

/// Injectable only through the library; CLI always uses the kernel probe.
pub fn initialize_with_storage(
    profile: &Profile,
    secrets: &Secrets,
    probe: &impl StorageProbe,
) -> Result<()> {
    profile.validate()?;
    secrets.validate()?;
    validate_storage(profile, probe)?;
    let state = secure_directory(&profile.state_dir, true)?;
    let _cache = secure_directory(&profile.cache_dir, true)?;
    let mount = secure_directory(&profile.mount_dir, true)?;
    ensure!(
        fs::read_dir(pinned_path(&mount))?.next().is_none(),
        "mount directory is not empty"
    );
    let parent = pinned_path(&state);
    ensure!(
        !parent.join("profile.toml").exists() && !parent.join("secrets.toml").exists(),
        "profile already initialized; refusing overwrite"
    );
    let encoded = Zeroizing::new(toml::to_string(secrets)?);
    atomic_write(&state, "secrets.toml", encoded.as_bytes())?;
    // On failure secrets remain private; retry requires explicit operator recovery, never overwrite.
    atomic_write(&state, "profile.toml", toml::to_string(profile)?.as_bytes())?;
    Ok(())
}

fn check_version(program: &str, arg: &str, minimum: (u32, u32, u32)) -> Result<()> {
    let output = Command::new(program)
        .arg(arg)
        .output()
        .with_context(|| format!("install required executable: {program}"))?;
    ensure!(output.status.success(), "{program} version check failed");
    let text = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let version = text
        .split_whitespace()
        .find_map(|token| {
            let parts: Vec<_> = token.trim_start_matches('v').split('.').collect();
            if parts.len() < 2 {
                return None;
            }
            Some((
                parts[0].parse::<u32>().ok()?,
                parts[1].parse::<u32>().ok()?,
                parts
                    .get(2)
                    .and_then(|s| {
                        s.split(|c: char| !c.is_ascii_digit())
                            .next()?
                            .parse::<u32>()
                            .ok()
                    })
                    .unwrap_or(0),
            ))
        })
        .context("cannot parse dependency version")?;
    ensure!(
        version >= minimum,
        "{program} is too old; requires {}.{}.{}",
        minimum.0,
        minimum.1,
        minimum.2
    );
    Ok(())
}

/// Read-only host preflight except a temporary sparse probe, removed on every exit.
/// Port checks are advisory snapshots; serve must recheck before binding.
pub fn doctor(profile: &Profile) -> Result<Vec<String>> {
    profile.validate()?;
    validate_storage(profile, &LinuxStorage)?;
    for (program, arg, minimum) in [
        ("rclone", "version", (1, 70, 0)),
        ("smbd", "--version", (4, 19, 0)),
        ("testparm", "--version", (4, 19, 0)),
        ("pdbedit", "--version", (4, 19, 0)),
        ("fusermount3", "--version", (3, 14, 0)),
    ] {
        check_version(program, arg, minimum)?;
    }
    let iface = CString::new(profile.interface.as_str())?;
    ensure!(
        unsafe { libc::if_nametoindex(iface.as_ptr()) } != 0,
        "selected interface does not exist; select a LAN/VPN interface"
    );
    let flags = fs::read_to_string(
        Path::new("/sys/class/net")
            .join(&profile.interface)
            .join("flags"),
    )?;
    let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16)?;
    ensure!(
        flags & libc::IFF_LOOPBACK as u32 == 0 && flags & libc::IFF_UP as u32 != 0,
        "selected LAN/VPN interface must be up and non-loopback"
    );
    if let Some(address) = profile.listen_address {
        ensure!(
            interface_has_address(&profile.interface, address)?,
            "SMB listen address is not assigned to the selected interface"
        );
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open("/dev/fuse")
        .context("FUSE unavailable: install fuse3 and grant gateway user /dev/fuse access")?;
    let state = secure_directory(&profile.state_dir, false)?;
    Secrets::from_protected_file(&pinned_path(&state).join("secrets.toml"))?;
    let cache = secure_directory(&profile.cache_dir, false)?;
    let mount = secure_directory(&profile.mount_dir, false)?;
    ensure!(
        fs::read_dir(pinned_path(&mount))?.next().is_none(),
        "mount path must be empty before starting"
    );
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::fstatvfs(cache.as_raw_fd(), stats.as_mut_ptr()) } == 0,
        "cannot measure cache free space"
    );
    let stats = unsafe { stats.assume_init() };
    let available = (stats.f_bavail as u128) * (stats.f_frsize as u128);
    ensure!(
        available >= profile.min_free_bytes as u128,
        "insufficient free cache space"
    );
    let mut probe = tempfile::tempfile_in(pinned_path(&cache))?;
    probe.set_len(64 * 1024 * 1024)?;
    probe.write_all(b"sparse probe")?;
    probe.sync_all()?;
    ensure!(
        probe.metadata()?.blocks() * 512 < 1024 * 1024,
        "cache filesystem does not support sparse files"
    );
    let mut listeners = Vec::new();
    let mut ipv6_listeners = Vec::new();
    for port in [445, profile.control_port] {
        listeners.push(TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).with_context(|| format!("port {port} unavailable (conflict or missing privilege); do not replace host services"))?);
        match socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        ) {
            Ok(socket) => {
                socket.set_only_v6(true)?;
                let address = std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port));
                socket.bind(&address.into()).with_context(|| {
                    format!("IPv6 port {port} unavailable; do not replace host services")
                })?;
                socket.listen(1)?;
                ipv6_listeners.push(socket);
            }
            Err(error) if error.raw_os_error() == Some(libc::EAFNOSUPPORT) => {}
            Err(error) => return Err(error.into()),
        }
    }
    if profile.control_port == 445 {
        bail!("control port conflicts with SMB");
    }
    Ok(vec!["Host preflight passed; no services started. Port availability is a snapshot, not a reservation.".into(), "Operator must verify selected interface is private LAN/VPN and firewall blocks public TCP 445. Cloud credentials/connectivity are not tested in step 1.".into()])
}

fn interface_has_address(interface: &str, address: Ipv4Addr) -> Result<bool> {
    let mut head = std::ptr::null_mut();
    ensure!(
        unsafe { libc::getifaddrs(&mut head) } == 0,
        "cannot inspect interface addresses"
    );
    let mut current = head;
    let mut found = false;
    while !current.is_null() {
        let entry = unsafe { &*current };
        if !entry.ifa_name.is_null()
            && !entry.ifa_addr.is_null()
            && unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }.to_bytes()
                == interface.as_bytes()
            && unsafe { (*entry.ifa_addr).sa_family } as i32 == libc::AF_INET
        {
            let socket = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
            found |= Ipv4Addr::from(socket.sin_addr.s_addr.to_ne_bytes()) == address;
        }
        current = entry.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    Ok(found)
}
