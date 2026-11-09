//! One local instance per persistent state directory. All restarts MUST use the same
//! state/cache/mount paths. Second gateways and external bucket writers are unsupported:
//! flock is not distributed locking. Dirty cache and recovery manifests are never deleted.
use crate::{
    config::{CryptConfig, Profile, Secrets},
    health::{self, Health, LocalControl},
};
use anyhow::{bail, ensure, Context, Result};
use serde_json::json;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

pub struct InstanceLock(File);
impl InstanceLock {
    pub fn acquire(state: &Path) -> Result<Self> {
        private_directory(state)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(state.join("instance.lock"))?;
        ensure!(file.metadata()?.nlink() == 1, "unsafe instance lock");
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "another local gateway holds the instance lock; concurrent writers unsupported"
        );
        Ok(Self(file))
    }
}
impl Drop for InstanceLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
fn private_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o777 == 0o700,
        "gateway directories must be private owned directories"
    );
    Ok(())
}
fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    File::open(path.parent().context("missing parent")?)?.sync_all()?;
    Ok(())
}
fn read_private(path: &Path) -> Result<String> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o777 == 0o600
            && m.len() < 65536,
        "unsafe runtime file"
    );
    let mut text = String::new();
    f.read_to_string(&mut text)?;
    Ok(text)
}
pub fn mount_args(p: &Profile) -> Vec<String> {
    vec![
        "mount".into(),
        CryptConfig::REMOTE.into(),
        p.mount_dir.display().to_string(),
        "--config".into(),
        "/dev/null".into(),
        "--cache-dir".into(),
        p.cache_dir.display().to_string(),
        "--vfs-cache-mode".into(),
        "full".into(),
        "--vfs-write-back".into(),
        format!("{}s", p.writeback_seconds),
        "--vfs-cache-max-size".into(),
        format!("{}B", p.cache_target_bytes),
        "--vfs-cache-min-free-space".into(),
        format!("{}B", p.min_free_bytes),
        "--vfs-read-ahead".into(),
        "16M".into(),
        "--buffer-size".into(),
        "8M".into(),
        "--vfs-read-chunk-size".into(),
        "8M".into(),
        "--vfs-read-chunk-size-limit".into(),
        "64M".into(),
        "--transfers".into(),
        "4".into(),
        "--checkers".into(),
        "4".into(),
        "--s3-upload-concurrency".into(),
        "2".into(),
        "--rc".into(),
        "--rc-addr".into(),
        format!("127.0.0.1:{}", p.control_port),
        "--rc-user".into(),
        "gateway".into(),
    ]
}
fn free_bytes(path: &Path) -> Result<u64> {
    let file = File::open(path)?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::fstatvfs(file.as_raw_fd(), stats.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    let stats = unsafe { stats.assume_init() };
    Ok((stats.f_bavail as u128 * stats.f_frsize as u128).min(u64::MAX as u128) as u64)
}
pub fn mounted(path: &Path) -> Result<bool> {
    // mountinfo escapes whitespace and backslash using octal escapes.
    let encoded = path
        .to_str()
        .context("non UTF-8 mount path")?
        .replace('\\', "\\134")
        .replace(' ', "\\040")
        .replace('\t', "\\011")
        .replace('\n', "\\012");
    Ok(fs::read_to_string("/proc/self/mountinfo")?
        .lines()
        .any(|line| {
            line.split_whitespace().nth(4) == Some(encoded.as_str())
                && line.contains(" - fuse.rclone ")
        }))
}

/// Injectable lifecycle seam: stop SMB workers before drain; start only after readiness.
pub trait Runtime {
    fn alive(&mut self) -> Result<bool>;
    fn mounted(&self) -> Result<bool>;
    fn health(&mut self) -> Result<Health>;
    fn stop(&mut self) -> Result<()>;
}
pub fn wait_ready(runtime: &mut impl Runtime, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        ensure!(
            runtime.alive()?,
            "rclone exited before mount readiness; cache retained"
        );
        if runtime.mounted()? {
            match runtime.health() {
                Ok(status) if status.process_alive && status.mount_ready && runtime.alive()? => {
                    return Ok(())
                }
                Err(error) if Instant::now() >= deadline => {
                    return Err(error.context("mount readiness failed; SMB must not start"))
                }
                _ => {}
            }
        }
        ensure!(
            Instant::now() < deadline,
            "mount readiness timeout; SMB must not start"
        );
        thread::sleep(Duration::from_millis(100));
    }
}
pub fn shutdown(
    runtime: &mut impl Runtime,
    stop_writes: impl FnOnce() -> Result<()>,
    timeout: Duration,
) -> Result<()> {
    stop_writes()?;
    let deadline = Instant::now() + timeout;
    let drained = loop {
        if !runtime.alive().unwrap_or(false) {
            break false;
        }
        if let Ok(status) = runtime.health() {
            eprintln!("drain: {}", serde_json::to_string(&status)?);
            if status.drained() {
                break true;
            }
        }
        if Instant::now() >= deadline {
            break false;
        }
        thread::sleep(Duration::from_millis(100));
    };
    let stopped = runtime.stop();
    ensure!(drained, "UNSYNCED DATA: upload drain timed out or child/control failed; persistent cache and recovery state retained; restart with unchanged profile");
    stopped
}

/// Versioned metadata deliberately excludes R2 credentials (rotation is supported).
pub fn recovery_manifest(profile: &Profile) -> Result<String> {
    let crypt = profile.encryption.as_ref().context("crypt required")?;
    Ok(json!({"version": 2, "args": mount_args(profile),
        "identity": crypt.identity(profile)})
    .to_string())
}

const IDENTITY_MARKER: &str = "crypt:.gateway-identity-v1";

// Obscuring is reversible encoding, NOT encryption. The child environment is
// restricted, but same-UID processes and root are trusted and can read secrets.
fn crypt_command(profile: &Profile, secrets: &Secrets) -> Result<Command> {
    crate::config::validate_storage(profile, &crate::config::LinuxStorage)?;
    let tmp = profile.state_dir.join("tmp");
    if !tmp.exists() {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&tmp)?;
    }
    private_directory(&tmp)?;
    let crypt = profile.encryption.as_ref().context("crypt required")?;
    let password = obscure(&secrets.crypt_password)?;
    let salt = obscure(&secrets.crypt_salt)?;
    let mut command = Command::new("rclone");
    command
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", &profile.state_dir)
        .env("TMPDIR", &tmp)
        .env("XDG_CACHE_HOME", &profile.cache_dir)
        .env("RCLONE_CONFIG_R2_TYPE", "s3")
        .env("RCLONE_CONFIG_R2_PROVIDER", "Cloudflare")
        .env("RCLONE_CONFIG_R2_ENDPOINT", &profile.endpoint)
        .env("RCLONE_CONFIG_R2_ACCESS_KEY_ID", &secrets.access_key_id)
        .env(
            "RCLONE_CONFIG_R2_SECRET_ACCESS_KEY",
            &secrets.secret_access_key,
        )
        .env("RCLONE_CONFIG_R2_REGION", "auto")
        // Object-scoped R2 tokens cannot perform bucket-administration checks.
        .env("RCLONE_CONFIG_R2_NO_CHECK_BUCKET", "true")
        .env("RCLONE_CONFIG_CRYPT_TYPE", "crypt")
        .env(
            "RCLONE_CONFIG_CRYPT_REMOTE",
            crypt.underlying_remote(&profile.bucket),
        )
        .env(
            "RCLONE_CONFIG_CRYPT_FILENAME_ENCRYPTION",
            CryptConfig::FILENAME_ENCRYPTION,
        )
        .env(
            "RCLONE_CONFIG_CRYPT_DIRECTORY_NAME_ENCRYPTION",
            CryptConfig::DIRECTORY_ENCRYPTION,
        )
        .env("RCLONE_CONFIG_CRYPT_PASSWORD", password.as_str())
        .env("RCLONE_CONFIG_CRYPT_PASSWORD2", salt.as_str());
    Ok(command)
}

fn obscure(value: &str) -> Result<zeroize::Zeroizing<String>> {
    let mut command = Command::new("rclone");
    command
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .args(["obscure", "--config", "/dev/null", "-"]);
    let bytes = run_private(&mut command, Some(value.as_bytes()), 4096)?;
    let text = zeroize::Zeroizing::new(
        String::from_utf8(bytes.to_vec())
            .map_err(|_| anyhow::anyhow!("invalid obscure response"))?,
    );
    ensure!(!text.trim().is_empty(), "empty obscure response");
    Ok(zeroize::Zeroizing::new(text.trim().to_owned()))
}

// Bounded output and deadline; never include child stderr or secret input in errors.
fn run_private(
    command: &mut Command,
    input: Option<&[u8]>,
    limit: u64,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    let mut child = command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("start installed rclone")?;
    if let Some(input) = input {
        let result = child
            .stdin
            .take()
            .context("missing rclone stdin")?
            .write_all(input);
        if result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
            bail!("rclone stdin failed");
        }
    }
    let mut output = child.stdout.take().context("missing rclone stdout")?;
    if unsafe { libc::fcntl(output.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
        let _ = child.kill();
        let _ = child.wait();
        bail!("cannot bound rclone output");
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut status = None;
    loop {
        let mut buffer = zeroize::Zeroizing::new([0u8; 4096]);
        match output.read(&mut *buffer) {
            Ok(0) if status.is_some() => break,
            Ok(n) => bytes.extend_from_slice(&buffer[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                bail!("rclone output failed");
            }
        }
        if Instant::now() >= deadline || bytes.len() as u64 > limit {
            let _ = child.kill();
            let _ = child.wait();
            bail!("rclone operation exceeded deadline/output limit");
        }
        if status.is_none() {
            status = child.try_wait()?;
        }
        thread::sleep(Duration::from_millis(10));
    }
    ensure!(
        status.is_some_and(|s| s.success()),
        "rclone operation failed (details suppressed)"
    );
    Ok(bytes)
}

fn verify_destination(profile: &Profile, command: &mut Command) -> Result<()> {
    // A fresh command is required because Command accumulates arguments.
    let mut probe = Command::new(command.get_program());
    probe
        .env_clear()
        .envs(command.get_envs().filter_map(|(k, v)| v.map(|v| (k, v))))
        .args(["cat", IDENTITY_MARKER, "--config", "/dev/null"]);
    let bytes = run_private(&mut probe, None, 4096)
        .context("encrypted identity unavailable: wrong keys or uninitialized destination; refusing to serve")?;
    let expected = profile
        .encryption
        .as_ref()
        .context("crypt required")?
        .identity(profile);
    ensure!(
        bytes.as_slice() == expected.as_bytes(),
        "encrypted destination identity mismatch"
    );
    Ok(())
}

/// Verify an existing encrypted marker without creating or adopting a destination.
pub fn verify_initialized_destination(profile: &Profile, secrets: &Secrets) -> Result<()> {
    profile.validate()?;
    secrets.validate()?;
    crate::config::validate_storage(profile, &crate::config::LinuxStorage)?;
    let _lock = InstanceLock::acquire(&profile.state_dir)?;
    verify_destination(profile, &mut crypt_command(profile, secrets)?)
}

/// Explicit opt-in initialization ONLY, never called by startup or local initialize.
/// Requires exclusive ownership of the destination: remote writers are unsupported.
/// No overwrite or adoption of unexplained existing objects is permitted.
pub fn initialize_destination(profile: &Profile, secrets: &Secrets) -> Result<()> {
    profile.validate()?;
    secrets.validate()?;
    crate::config::validate_storage(profile, &crate::config::LinuxStorage)?;
    let _lock = InstanceLock::acquire(&profile.state_dir)?;
    ensure!(
        fs::read_dir(&profile.cache_dir)?.next().is_none()
            && !profile.state_dir.join("recovery.json").exists(),
        "destination initialization requires a fresh cache and no recovery manifest"
    );
    let crypt = profile.encryption.as_ref().context("crypt required")?;
    let mut listing = crypt_command(profile, secrets)?;
    listing.args([
        "lsf",
        &crypt.underlying_remote(&profile.bucket),
        "--config",
        "/dev/null",
    ]);
    ensure!(
        run_private(&mut listing, None, 4096)?.is_empty(),
        "nonempty destination refused; never adopt or overwrite existing objects"
    );
    let mut write = crypt_command(profile, secrets)?;
    write.args([
        "rcat",
        IDENTITY_MARKER,
        "--config",
        "/dev/null",
        "--immutable",
    ]);
    run_private(&mut write, Some(crypt.identity(profile).as_bytes()), 4096)?;
    verify_destination(profile, &mut crypt_command(profile, secrets)?)
}

pub struct Gateway {
    child: Child,
    control: LocalControl,
    profile: Profile,
    _lock: InstanceLock,
    storage: crate::config::StorageIdentity,
}
impl Gateway {
    pub fn start(profile: Profile, timeout: Duration) -> Result<Self> {
        profile.validate()?;
        let storage = crate::config::validate_storage(&profile, &crate::config::LinuxStorage)?;
        let lock = InstanceLock::acquire(&profile.state_dir)?;
        private_directory(&profile.cache_dir)?;
        private_directory(&profile.mount_dir)?;
        ensure!(
            !mounted(&profile.mount_dir)?,
            "mount already exists; recover manually before restart"
        );
        ensure!(
            fs::read_dir(&profile.mount_dir)?.next().is_none(),
            "mount directory not empty"
        );
        let mut probe = tempfile::tempfile_in(&profile.cache_dir)?;
        probe.set_len(64 * 1024 * 1024)?;
        probe.write_all(b"sparse")?;
        probe.sync_all()?;
        ensure!(
            probe.metadata()?.blocks() * 512 < 1024 * 1024,
            "cache must support sparse files"
        );
        // Low space is reported, not grounds to delete dirty cache or prevent recovery.
        let args = mount_args(&profile);
        let manifest = recovery_manifest(&profile)?;
        let recovery = profile.state_dir.join("recovery.json");
        if recovery.exists() {
            ensure!(read_private(&recovery)? == manifest, "recovery configuration changed; restore original flags/paths before uploading dirty cache");
        } else {
            ensure!(
                fs::read_dir(&profile.cache_dir)?.next().is_none(),
                "cache without recovery identity refused; retain it for manual recovery"
            );
        }
        let password_path = profile.state_dir.join("control.password");
        if !password_path.exists() {
            let mut random = [0u8; 32];
            File::open("/dev/urandom")?.read_exact(&mut random)?;
            let password: String = random.iter().map(|b| format!("{b:02x}")).collect();
            private_write(&password_path, password.as_bytes())?;
        }
        let password = read_private(&password_path)?;
        ensure!(
            password.len() == 64 && password.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid RC password"
        );
        let secrets = Secrets::from_protected_file(&profile.state_dir.join("secrets.toml"))?;
        let listener =
            std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, profile.control_port))
                .context("RC port already in use")?;
        drop(listener);
        let mut command = crypt_command(&profile, &secrets)?;
        verify_destination(&profile, &mut command)?;
        if !recovery.exists() {
            private_write(&recovery, manifest.as_bytes())?;
        }
        let child = command
            .args(args)
            .env("RCLONE_RC_PASS", &password)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("start installed rclone")?;
        let mut gateway = Self {
            child,
            control: LocalControl::new(profile.control_port, &password),
            profile,
            _lock: lock,
            storage,
        };
        wait_ready(&mut gateway, timeout)?;
        Ok(gateway)
    }
}
impl Runtime for Gateway {
    fn alive(&mut self) -> Result<bool> {
        Ok(self.child.try_wait()?.is_none())
    }
    fn mounted(&self) -> Result<bool> {
        Ok(
            crate::config::validate_storage(&self.profile, &crate::config::LinuxStorage)
                .is_ok_and(|identity| identity == self.storage)
                && mounted(&self.profile.mount_dir)?,
        )
    }
    fn health(&mut self) -> Result<Health> {
        health::verify(&self.control)?;
        let alive = self.alive()?;
        health::snapshot(
            &self.control,
            CryptConfig::REMOTE,
            alive,
            self.mounted()?,
            free_bytes(&self.profile.cache_dir)?,
            self.profile.min_free_bytes,
            self.profile.cache_target_bytes,
        )
    }
    fn stop(&mut self) -> Result<()> {
        if self.alive()? {
            unsafe {
                libc::kill(self.child.id() as i32, libc::SIGTERM);
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.alive()? && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(100));
            }
            if self.alive()? {
                self.child.kill()?;
            }
        }
        self.child.wait()?;
        if mounted(&self.profile.mount_dir)? {
            // Child is stopped; lazy detach cannot expose writes to the stale mount.
            let mut unmount = Command::new("fusermount3")
                .args(["-uz", "--"])
                .arg(&self.profile.mount_dir)
                .spawn()?;
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(status) = unmount.try_wait()? {
                    ensure!(status.success(), "unmount failed");
                    break;
                }
                if Instant::now() >= deadline {
                    unmount.kill()?;
                    unmount.wait()?;
                    bail!("unmount timeout; cache retained");
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
        Ok(())
    }
}
impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

pub fn status(profile: &Profile) -> Result<Health> {
    let password = read_private(&profile.state_dir.join("control.password"))?;
    let control = LocalControl::new(profile.control_port, &password);
    health::verify(&control)?;
    // Authenticated core/version response establishes process liveness, not backend health.
    health::snapshot(
        &control,
        CryptConfig::REMOTE,
        true,
        mounted(&profile.mount_dir)?,
        free_bytes(&profile.cache_dir)?,
        profile.min_free_bytes,
        profile.cache_target_bytes,
    )
}
pub fn serve(profile: Profile) -> Result<()> {
    use crate::samba;
    use std::os::unix::fs::PermissionsExt;
    samba::check_identity()?;
    profile.validate()?;
    crate::config::validate_storage(&profile, &crate::config::LinuxStorage)?;
    let stopping = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, stopping.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, stopping.clone())?;
    // Open before mount. A sealed (000) directory after a crash requires explicit
    // administrator recovery: stop all stale smbd workers, unmount, then chmod 700.
    private_directory(&profile.mount_dir).context("mount directory must be 0700; if sealed after a crash, stop stale Samba workers and unmount before administrator restores 0700")?;
    ensure!(
        !mounted(&profile.mount_dir)?,
        "stale mount; recover manually"
    );
    let underlay = File::open(&profile.mount_dir)?;
    let secrets = Secrets::from_protected_file(&profile.state_dir.join("secrets.toml"))?;
    let mut gateway = Gateway::start(profile.clone(), Duration::from_secs(30))?;
    let config = samba::prepare(&profile, &secrets)?;
    samba::seal_underlay(&underlay)?;
    let mut smb = start_writers(&mut gateway, || samba::Samba::start(&config))?;
    eprintln!("Authenticated encrypted SMB3 ready; all clients must use this single gateway.");
    while !stopping.load(Ordering::Relaxed) {
        contain_mount_loss(&mut gateway, || smb.stop())?;
        ensure!(
            smb.alive()?,
            "Samba exited; check TCP 445 privilege/conflicts; cache retained"
        );
        // Do not block mount supervision on remote backend health requests.
        thread::sleep(Duration::from_millis(100));
    }
    let result = shutdown(&mut gateway, || smb.stop(), Duration::from_secs(60));
    // Only a successful orderly shutdown unseals the directory automatically.
    if result.is_ok() {
        underlay.set_permissions(fs::Permissions::from_mode(0o700))?;
    }
    result
}

pub fn start_writers<T>(
    runtime: &mut impl Runtime,
    start: impl FnOnce() -> Result<T>,
) -> Result<T> {
    wait_ready(runtime, Duration::ZERO)?;
    ensure!(
        runtime.mounted()? && runtime.alive()?,
        "mount lost before SMB startup"
    );
    start()
}

pub fn contain_mount_loss(
    runtime: &mut impl Runtime,
    stop: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if !runtime.alive().unwrap_or(false) || !runtime.mounted().unwrap_or(false) {
        stop()?;
        bail!("SMB stopped: rclone child/mount lost; UNSYNCED DATA may remain in persistent cache");
    }
    Ok(())
}
