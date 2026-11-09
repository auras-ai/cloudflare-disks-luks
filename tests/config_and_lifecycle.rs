use cloudflare_disk::config::{Profile, Secrets, StorageIdentity, StorageProbe};

struct LabStorage;
impl StorageProbe for LabStorage {
    fn inspect(&self, _: &Path) -> anyhow::Result<StorageIdentity> {
        Ok(StorageIdentity("test-only".into()))
    }
}
fn initialize(p: &Profile, s: &Secrets) -> anyhow::Result<()> {
    cloudflare_disk::config::initialize_with_storage(p, s, &LabStorage)
}

#[test]
fn storage_mount_provenance_and_no_write_failure() {
    use cloudflare_disk::config::{initialize as secure_init, inspect_mountinfo};
    let root = tempfile::tempdir().unwrap();
    let p = profile(root.path());
    assert!(secure_init(&p, &secrets()).is_err());
    assert!(!p.state_dir.exists());
    assert!(!p.cache_dir.exists());
    let sys = tempfile::tempdir().unwrap();
    let device = sys.path().join("253:0");
    fs::create_dir_all(device.join("dm")).unwrap();
    fs::create_dir(device.join("slaves")).unwrap();
    let line = format!(
        "42 1 253:0 / {} rw - ext4 /dev/dm-0 rw",
        root.path().display()
    );
    assert!(inspect_mountinfo(root.path(), "", sys.path()).is_err());
    assert!(inspect_mountinfo(root.path(), &line, sys.path()).is_err());
    fs::write(device.join("dm/uuid"), "CRYPT-LUKS1-wrong").unwrap();
    assert!(inspect_mountinfo(root.path(), &line, sys.path()).is_err());
    fs::write(device.join("dm/uuid"), "CRYPT-LUKS2-test").unwrap();
    let identity = inspect_mountinfo(root.path(), &line, sys.path()).unwrap();
    assert!(inspect_mountinfo(root.path(), &line.replace(" / ", " /subdir "), sys.path()).is_err());
    assert_ne!(
        identity,
        inspect_mountinfo(root.path(), &line.replacen("42", "43", 1), sys.path()).unwrap()
    );
    initialize(&p, &secrets()).unwrap();
    fs::write(p.cache_dir.join("dirty"), b"retain").unwrap();
    assert!(gateway::Gateway::start(p.clone(), Duration::ZERO).is_err());
    assert_eq!(fs::read(p.cache_dir.join("dirty")).unwrap(), b"retain");
    assert!(!p.state_dir.join("control.password").exists());
}
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::Path,
    process::Command,
};

#[test]
fn samba_security_and_injection() {
    use cloudflare_disk::samba;
    let root = tempfile::tempdir().unwrap();
    let p = profile(root.path());
    let text = samba::configuration(&p).unwrap();
    for required in [
        "server min protocol = SMB3_00",
        "server smb encrypt = required",
        "map to guest = Never",
        "guest ok = no",
        "valid users = r2disk",
        "bind interfaces only = yes",
        "smb ports = 445",
        "locking = yes",
        "case sensitive = yes",
        "preserve case = yes",
        "follow symlinks = no",
        "passdb backend = tdbsam:",
        "/private/passdb.tdb",
        "/pid",
        "/state",
    ] {
        assert!(text.contains(required), "{required}");
    }
    assert_eq!(text.lines().filter(|l| l.starts_with('[')).count(), 2);
    assert!(!text.contains(&secrets().smb_password));
    assert!(!gateway::mount_args(&p).contains(&"--allow-other".to_string()));
    for attack in ["evil\n[global]", "evil%U", "evil\rpath=x", "evil;foo"] {
        let mut bad = p.clone();
        bad.share = attack.into();
        assert!(samba::configuration(&bad).is_err());
        bad = p.clone();
        bad.interface = attack.into();
        assert!(samba::configuration(&bad).is_err());
        bad = p.clone();
        bad.mount_dir = root.path().join(attack);
        assert!(samba::configuration(&bad).is_err());
    }
}

#[test]
fn samba_ordering_and_mount_loss_containment() {
    let started = Cell::new(false);
    let mut runtime = child();
    runtime.mounted = false;
    assert!(gateway::start_writers(&mut runtime, || {
        started.set(true);
        Ok(())
    })
    .is_err());
    assert!(!started.get());
    runtime.mounted = true;
    gateway::start_writers(&mut runtime, || {
        started.set(true);
        Ok(())
    })
    .unwrap();
    assert!(started.get());
    for failure in 0..2 {
        let mut runtime = child();
        runtime.mounted = failure != 0;
        runtime.alive = failure != 1;
        let stopped = Cell::new(false);
        assert!(gateway::contain_mount_loss(&mut runtime, || {
            stopped.set(true);
            Ok(())
        })
        .is_err());
        assert!(stopped.get());
    }
    // The physical underlay is inaccessible even before the supervisor polls.
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("underlay");
    fs::create_dir(&dir).unwrap();
    let fd = fs::File::open(&dir).unwrap();
    cloudflare_disk::samba::seal_underlay(&fd).unwrap();
    assert_eq!(fd.metadata().unwrap().permissions().mode() & 0o777, 0);
    if unsafe { libc::geteuid() } != 0 {
        assert!(fs::read_dir(&dir).is_err());
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn generated_samba_config_passes_installed_testparm() {
    let root = tempfile::tempdir().unwrap();
    let p = profile(root.path());
    for name in ["private", "pid", "lock", "state", "cache"] {
        fs::create_dir_all(p.state_dir.join("samba").join(name)).unwrap();
    }
    let config = root.path().join("smb.conf");
    fs::write(&config, cloudflare_disk::samba::configuration(&p).unwrap()).unwrap();
    let result = Command::new("testparm")
        .args(["-s", "--suppress-prompt"])
        .arg(&config)
        .output();
    match result {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("SKIP live config validation: testparm not installed")
        }
        result => {
            let output = result.unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!String::from_utf8_lossy(&output.stderr).contains("Unknown parameter"));
        }
    }
}

#[test]
fn installed_pdbedit_provisions_private_database_without_root_or_argv_secret() {
    use std::io::Write;
    use std::process::Stdio;
    if Command::new("pdbedit").arg("--version").output().is_err() {
        eprintln!("SKIP password database check: pdbedit not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let p = profile(root.path());
    for name in ["private", "pid", "lock", "state", "cache"] {
        fs::create_dir_all(p.state_dir.join("samba").join(name)).unwrap();
    }
    let config = root.path().join("smb.conf");
    fs::write(&config, cloudflare_disk::samba::configuration(&p).unwrap()).unwrap();
    let user = Command::new("id").arg("-un").output().unwrap();
    let user = String::from_utf8(user.stdout).unwrap();
    // Only the temporary passdb is touched; reuse an existing Unix identity.
    for _ in 0..2 {
        let mut child = Command::new("pdbedit")
            .arg("--configfile")
            .arg(&config)
            .args(["--create", "--user", user.trim(), "--password-from-stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(
            child.stdin.take().unwrap(),
            "test-password-123\ntest-password-123"
        )
        .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(p.state_dir.join("samba/private/passdb.tdb").is_file());
    if Command::new("smbclient").arg("--version").output().is_err()
        || Command::new("smbd").arg("--version").output().is_err()
    {
        eprintln!("SKIP loopback SMB check: smbd/smbclient not installed");
        return;
    }
    fs::create_dir(&p.mount_dir).unwrap();
    fs::write(p.mount_dir.join("Case.txt"), b"upper").unwrap();
    fs::write(p.mount_dir.join("case.txt"), b"lower").unwrap();
    fs::write(p.mount_dir.join("caf\u{00e9}.txt"), b"unicode").unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let text = cloudflare_disk::samba::configuration(&p)
        .unwrap()
        .replace(
            &format!("interfaces = {}", p.interface),
            "interfaces = 127.0.0.1",
        )
        .replace("smb ports = 445", &format!("smb ports = {port}"))
        .replace(
            "valid users = r2disk",
            &format!("valid users = {}", user.trim()),
        );
    fs::write(&config, text).unwrap();
    drop(listener);
    let mut server = cloudflare_disk::samba::Samba::start(&config).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).is_err() {
        assert!(
            server.alive().unwrap(),
            "smbd exited: {:?}",
            fs::read_to_string(p.state_dir.join("samba/log.smbd"))
        );
        assert!(std::time::Instant::now() < deadline, "smbd startup timeout");
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut client = Command::new("smbclient")
        .arg(format!("//127.0.0.1/{}", p.share))
        .args([
            "-p",
            &port.to_string(),
            "-U",
            user.trim(),
            "--client-protection=encrypt",
            "-c",
            "ls",
        ])
        .env("PASSWD_FD", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(client.stdin.take().unwrap(), "test-password-123").unwrap();
    let output = client.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let listing = String::from_utf8_lossy(&output.stdout);
    for name in ["Case.txt", "case.txt", "caf\u{00e9}.txt"] {
        assert!(listing.contains(name), "{listing}");
    }
    let guest = Command::new("smbclient")
        .arg(format!("//127.0.0.1/{}", p.share))
        .args(["-p", &port.to_string(), "-N", "-U", "guest", "-c", "ls"])
        .output()
        .unwrap();
    assert!(!guest.status.success());
    server.stop().unwrap();
    server.stop().unwrap();
}

#[test]
fn encrypted_contract_roundtrip_and_legacy_refusal() {
    let root = tempfile::tempdir().unwrap();
    let p = profile(root.path());
    let encoded = toml::to_string(&p).unwrap();
    let restored: Profile = toml::from_str(&encoded).unwrap();
    assert_eq!(p.encryption, restored.encryption);
    restored.validate().unwrap();
    for prefix in [
        "",
        "/root",
        "foo/",
        "foo//bar",
        "../old",
        "foo/../old",
        "x:y",
        "x\\ny",
        "x y",
    ] {
        let mut value = toml::Value::try_from(&p).unwrap();
        value["encryption"]["prefix"] = prefix.into();
        let bad: Profile = value.try_into().unwrap();
        assert!(bad.validate().is_err());
    }
    let mut value = toml::Value::try_from(&p).unwrap();
    value["encryption"]["key_id"] = "bad".into();
    assert!(value.try_into::<Profile>().unwrap().validate().is_err());
    let mut legacy = p.clone();
    legacy.encryption = None;
    let path = root.path().join("legacy.toml");
    fs::write(&path, toml::to_string(&legacy).unwrap()).unwrap();
    let error = format!("{:#}", Profile::load(&path).unwrap_err());
    assert!(error.contains("legacy plaintext") && error.contains("NEW dedicated prefix"));
    assert!(initialize(&legacy, &secrets()).is_err());
    assert!(!p.state_dir.exists());
    fs::write(&path, encoded).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_cloudflare-disk"))
        .args(["serve", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(!result.status.success());
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(
        error.contains("r2disk") || error.contains("encrypted storage mount"),
        "{error}"
    );
    assert!(!p.state_dir.exists());
}

#[test]
fn crypt_secrets_required_and_diagnostics_redacted() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("secrets.toml");
    for field in ["crypt_password", "crypt_salt"] {
        for invalid in [
            None,
            Some(""),
            Some("short"),
            Some("private-secret-value\ninvalid"),
        ] {
            let mut value = toml::Value::try_from(secrets()).unwrap();
            match invalid {
                None => {
                    value.as_table_mut().unwrap().remove(field);
                }
                Some(text) => {
                    value[field] = text.into();
                }
            }
            fs::write(&input, toml::to_string(&value).unwrap()).unwrap();
            fs::set_permissions(&input, fs::Permissions::from_mode(0o600)).unwrap();
            let error = format!("{:#}", Secrets::from_protected_file(&input).unwrap_err());
            assert!(!error.contains("private-secret-value"));
            assert!(!error.contains(&secrets().crypt_password));
            assert!(!error.contains(&secrets().crypt_salt));
        }
    }
    let s = secrets();
    assert!(!format!("{s:?}").contains(&s.crypt_password));
    assert!(!toml::to_string(&profile(root.path()))
        .unwrap()
        .contains(&s.crypt_salt));
}

fn profile(root: &Path) -> Profile {
    let mut p: Profile = toml::from_str(include_str!("../config/example.toml")).unwrap();
    p.state_dir = root.join("state");
    p.cache_dir = root.join("cache");
    p.mount_dir = root.join("mount");
    p
}

fn secrets() -> Secrets {
    Secrets {
        access_key_id: "a".repeat(32),
        secret_access_key: "b".repeat(64),
        smb_password: "unique-password-123".into(),
        crypt_password: "crypt-password-private-123".into(),
        crypt_salt: "crypt-salt-private-456".into(),
    }
}

#[test]
fn private_atomic_initialization_and_no_overwrite() {
    let root = tempfile::tempdir().unwrap();
    let p = profile(root.path());
    initialize(&p, &secrets()).unwrap();
    for path in [&p.state_dir, &p.cache_dir, &p.mount_dir] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    for name in ["profile.toml", "secrets.toml"] {
        assert_eq!(
            fs::metadata(p.state_dir.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    Secrets::from_protected_file(&p.state_dir.join("secrets.toml")).unwrap();
    let original = fs::read(p.state_dir.join("profile.toml")).unwrap();
    let original_secrets = fs::read(p.state_dir.join("secrets.toml")).unwrap();
    assert!(initialize(&p, &secrets()).is_err());
    assert_eq!(
        original,
        fs::read(p.state_dir.join("profile.toml")).unwrap()
    );
    assert_eq!(
        original_secrets,
        fs::read(p.state_dir.join("secrets.toml")).unwrap()
    );
    assert_eq!(fs::read_dir(&p.state_dir).unwrap().count(), 2);
}

#[test]
fn rejects_injection_and_path_aliases() {
    let root = tempfile::tempdir().unwrap();
    let base = profile(root.path());
    base.validate().unwrap();
    for attack in [
        "x\n[global]",
        "$(touch /tmp/pwn)",
        "x;evil",
        "x\rfoo",
        "x\0foo",
    ] {
        for field in 0..5 {
            let mut p = base.clone();
            match field {
                0 => p.bucket = attack.into(),
                1 => p.endpoint = attack.into(),
                2 => p.share = attack.into(),
                3 => p.interface = attack.into(),
                _ => p.cache_dir = root.path().join(attack),
            }
            // Dollar syntax is harmless in paths because no shell is invoked.
            if field != 4 || attack != "$(touch /tmp/pwn)" {
                assert!(p.validate().is_err(), "{field}");
            }
        }
    }
    let mut p = base.clone();
    p.cache_dir = p.state_dir.join("nested");
    assert!(p.validate().is_err());
    p.cache_dir = root.path().join("../alias");
    assert!(p.validate().is_err());
    p.cache_dir = "relative".into();
    assert!(p.validate().is_err());
    symlink(root.path(), root.path().join("alias")).unwrap();
    p.cache_dir = root.path().join("alias/cache");
    assert!(p.validate().is_err());
    for endpoint in [
        "https://user:pass@example.com",
        "http://example.com",
        "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com/path",
    ] {
        p = base.clone();
        p.endpoint = endpoint.into();
        assert!(p.validate().is_err());
    }
}

#[test]
fn refuses_unsafe_existing_directories_and_mount_contents() {
    let root = tempfile::tempdir().unwrap();
    let p = profile(root.path());
    fs::create_dir(&p.cache_dir).unwrap();
    fs::set_permissions(&p.cache_dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(initialize(&p, &secrets()).is_err());
    assert_eq!(
        fs::metadata(&p.cache_dir).unwrap().permissions().mode() & 0o777,
        0o755
    );
    fs::set_permissions(&p.cache_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(&p.mount_dir).unwrap();
    fs::set_permissions(&p.mount_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(p.mount_dir.join("host-file"), "preserve").unwrap();
    assert!(initialize(&p, &secrets()).is_err());
}

#[test]
fn protected_input_and_redaction() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("input");
    fs::write(&input, toml::to_string(&secrets()).unwrap()).unwrap();
    fs::set_permissions(&input, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Secrets::from_protected_file(&input).is_err());
    fs::set_permissions(&input, fs::Permissions::from_mode(0o600)).unwrap();
    let value = Secrets::from_protected_file(&input).unwrap();
    assert_eq!(format!("{value:?}"), "Secrets([REDACTED])");
    let alias = root.path().join("alias");
    symlink(&input, &alias).unwrap();
    assert!(Secrets::from_protected_file(&alias).is_err());
    fs::hard_link(&input, root.path().join("hardlink")).unwrap();
    assert!(Secrets::from_protected_file(&input).is_err());
    fs::remove_file(root.path().join("hardlink")).unwrap();
    fs::write(&input, "smb_password = 'SUPER-SECRET'\nmalformed").unwrap();
    let error = Secrets::from_protected_file(&input).unwrap_err();
    assert!(!format!("{error:#}").contains("SUPER-SECRET"));
    let mut s = secrets();
    s.smb_password = "password\nINJECTION".into();
    assert!(s.validate().is_err());
    fs::write(&input, "bucket = 'SUPER-SECRET'\nmalformed").unwrap();
    assert!(!format!("{:#}", Profile::load(&input).unwrap_err()).contains("SUPER-SECRET"));
}

#[test]
fn cli_validates_lifecycle_profiles_and_rejects_secret_flags() {
    for command in ["serve", "status"] {
        let result = Command::new(env!("CARGO_BIN_EXE_cloudflare-disk"))
            .args([command, "--config", "missing.toml"])
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("not implemented"));
    }
    let result = Command::new(env!("CARGO_BIN_EXE_cloudflare-disk"))
        .args(["init", "--config", "missing", "--secret-access-key"])
        .output()
        .unwrap();
    assert!(!result.status.success());
}

use cloudflare_disk::{
    gateway::{self, InstanceLock, Runtime},
    health::{self, Control, Health},
};
use serde_json::{json, Value};
use std::{cell::Cell, time::Duration};

// Fixtures match actual rclone v1.70.3 wire responses (queue, not the
// documented queued; inUse is a VFS reference count, NOT open writers).
struct FakeControl {
    pending: bool,
    offline: bool,
    missing_queue: bool,
}
impl Control for FakeControl {
    fn call(&self, method: &str, _: Value) -> anyhow::Result<Value> {
        Ok(match method {
            "core/version" => json!({"version":"v1.70.0"}),
            "rc/list" => json!({"commands": if self.missing_queue {
                vec![json!({"Path":"vfs/stats"})]
            } else { ["vfs/stats", "vfs/queue", "operations/stat", "core/stats"].iter().map(|p| json!({"Path":p})).collect() }}),
            "vfs/stats" => json!({"inUse":1, "diskCache": {
                "bytesUsed": 100, "erroredFiles": 0, "outOfSpace":false,
                "uploadsQueued": u64::from(self.pending), "uploadsInProgress":0 }}),
            "vfs/queue" => {
                json!({"queue": if self.pending {vec![json!({"tries":3, "delay":40.0, "uploading":false})]} else {vec![]}})
            }
            "core/stats" => json!({"errors": 3}),
            "operations/stat" if self.offline => anyhow::bail!("backend unavailable"),
            "operations/stat" => json!({"item":{"IsDir":true}}),
            _ => anyhow::bail!("unexpected call"),
        })
    }
}
fn telemetry(pending: bool) -> Health {
    health::snapshot(
        &FakeControl {
            pending,
            offline: false,
            missing_queue: false,
        },
        "r2:test",
        true,
        true,
        1000,
        10,
        500,
    )
    .unwrap()
}
#[test]
fn verifies_selected_api_and_separates_retry_backend_pressure_from_liveness() {
    let mut control = FakeControl {
        pending: true,
        offline: true,
        missing_queue: false,
    };
    assert_eq!(health::verify(&control).unwrap(), "v1.70.0");
    let status = health::snapshot(&control, "r2:test", true, true, 5, 10, 500).unwrap();
    assert!(status.process_alive && status.cache_pressure);
    assert!(!status.backend_reachable && !status.drained());
    assert_eq!(status.retrying_uploads, 1);
    assert_eq!(status.pending_uploads, 1);
    assert_eq!(status.transfer_errors, 3);
    control.missing_queue = true;
    assert!(health::verify(&control).is_err());
    assert!(telemetry(false).drained());
}
struct FakeChild {
    alive: bool,
    mounted: bool,
    pending: bool,
    control_failure: bool,
    writes_stopped: Cell<bool>,
    stopped: bool,
}
impl Runtime for FakeChild {
    fn alive(&mut self) -> anyhow::Result<bool> {
        Ok(self.alive)
    }
    fn mounted(&self) -> anyhow::Result<bool> {
        Ok(self.mounted)
    }
    fn health(&mut self) -> anyhow::Result<Health> {
        if self.control_failure {
            anyhow::bail!("control timeout");
        }
        let mut h = telemetry(self.pending);
        h.mount_ready = self.mounted;
        h.process_alive = self.alive;
        Ok(h)
    }
    fn stop(&mut self) -> anyhow::Result<()> {
        self.stopped = true;
        self.alive = false;
        Ok(())
    }
}
fn child() -> FakeChild {
    FakeChild {
        alive: true,
        mounted: true,
        pending: false,
        control_failure: false,
        writes_stopped: Cell::new(false),
        stopped: false,
    }
}
#[test]
fn actual_child_exit_is_detected_and_reaped_without_serving() {
    struct Process(std::process::Child);
    impl Runtime for Process {
        fn alive(&mut self) -> anyhow::Result<bool> {
            Ok(self.0.try_wait()?.is_none())
        }
        fn mounted(&self) -> anyhow::Result<bool> {
            Ok(false)
        }
        fn health(&mut self) -> anyhow::Result<Health> {
            anyhow::bail!("not ready")
        }
        fn stop(&mut self) -> anyhow::Result<()> {
            if self.alive()? {
                self.0.kill()?;
            }
            self.0.wait()?;
            Ok(())
        }
    }
    let mut process = Process(
        Command::new("/bin/sh")
            .args(["-c", "exit 23"])
            .spawn()
            .unwrap(),
    );
    process.0.wait().unwrap();
    assert!(gateway::wait_ready(&mut process, Duration::ZERO).is_err());
    assert!(gateway::shutdown(&mut process, || Ok(()), Duration::ZERO)
        .unwrap_err()
        .to_string()
        .contains("UNSYNCED DATA"));
    assert!(!process.alive().unwrap());
}

#[test]
fn readiness_failure_timeout_and_child_death_never_permit_writers() {
    let mut fake = child();
    fake.alive = false;
    assert!(gateway::wait_ready(&mut fake, Duration::ZERO)
        .unwrap_err()
        .to_string()
        .contains("exited"));
    fake.alive = true;
    fake.mounted = false;
    assert!(gateway::wait_ready(&mut fake, Duration::ZERO).is_err());
    fake.mounted = true;
    fake.control_failure = true;
    assert!(gateway::wait_ready(&mut fake, Duration::ZERO).is_err());
    fake.control_failure = false;
    gateway::wait_ready(&mut fake, Duration::ZERO).unwrap();
}
#[test]
fn shutdown_stops_writes_first_and_reports_unsynced_timeouts() {
    for failure in 0..4 {
        let mut fake = child();
        fake.pending = failure == 1;
        fake.control_failure = failure == 2;
        fake.alive = failure != 3;
        let writes = Cell::new(false);
        let result = gateway::shutdown(
            &mut fake,
            || {
                writes.set(true);
                Ok(())
            },
            Duration::ZERO,
        );
        assert!(writes.get() && fake.stopped);
        if failure == 0 {
            result.unwrap();
        } else {
            assert!(result.unwrap_err().to_string().contains("UNSYNCED DATA"));
        }
    }
    let mut fake = child();
    assert!(gateway::shutdown(
        &mut fake,
        || anyhow::bail!("SMB stop failed"),
        Duration::ZERO
    )
    .is_err());
    assert!(!fake.stopped);
    fake.writes_stopped.set(true);
}
#[test]
fn crypt_routing_and_versioned_recovery_identity() {
    use cloudflare_disk::config::CryptConfig;
    let root = tempfile::tempdir().unwrap();
    let p = profile(root.path());
    let crypt = p.encryption.as_ref().unwrap();
    assert_eq!(gateway::mount_args(&p)[1], CryptConfig::REMOTE);
    assert_eq!(
        crypt.underlying_remote(&p.bucket),
        format!("r2:{}/{}", p.bucket, crypt.prefix())
    );
    let manifest = gateway::recovery_manifest(&p).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    assert_eq!(parsed["version"], 2);
    for secret in [
        &secrets().crypt_password,
        &secrets().crypt_salt,
        &secrets().access_key_id,
        &secrets().secret_access_key,
    ] {
        assert!(!manifest.contains(secret));
    }
    let mut changed = p.clone();
    changed.bucket = "another-bucket".into();
    assert_ne!(manifest, gateway::recovery_manifest(&changed).unwrap());
    let text = toml::to_string(&p).unwrap();
    for (before, after) in [
        (crypt.prefix(), "different-prefix"),
        (crypt.key_id(), "fedcba9876543210fedcba9876543210"),
    ] {
        let changed: Profile = toml::from_str(&text.replace(before, after)).unwrap();
        assert_ne!(manifest, gateway::recovery_manifest(&changed).unwrap());
    }
    for extra in [
        "filename_encryption = 'off'",
        "directory_name_encryption = false",
    ] {
        assert!(toml::from_str::<Profile>(&format!("{text}\n{extra}\n")).is_err());
    }
}

#[test]
fn legacy_recovery_and_unidentified_cache_fail_before_child_start() {
    for legacy in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let p = profile(root.path());
        initialize(&p, &secrets()).unwrap();
        fs::write(p.cache_dir.join("dirty"), b"retain me").unwrap();
        if legacy {
            let path = p.state_dir.join("recovery.json");
            fs::write(&path, r#"{"args":[],"provider":"Cloudflare"}"#).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let error = match gateway::Gateway::start(p.clone(), Duration::ZERO) {
            Ok(_) => panic!("unsafe startup"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("storage mount"), "{error}");
        assert_eq!(fs::read(p.cache_dir.join("dirty")).unwrap(), b"retain me");
        assert!(!p.state_dir.join("control.password").exists());
        assert!(fs::read_dir(&p.mount_dir).unwrap().next().is_none());
        assert!(gateway::initialize_destination(&p, &secrets()).is_err());
    }
}

#[test]
fn crypt_rc_routes_vfs_backend_and_drain_telemetry() {
    struct Routes;
    impl Control for Routes {
        fn call(&self, method: &str, body: serde_json::Value) -> anyhow::Result<serde_json::Value> {
            if method != "core/stats" {
                assert_eq!(body["fs"], "crypt:", "{method}");
            }
            match method {
                "vfs/stats" => Ok(serde_json::json!({"diskCache": {"bytesUsed": 0,
                    "uploadsQueued": 0, "uploadsInProgress": 0, "erroredFiles": 0,
                    "outOfSpace": false}, "inUse": 0})),
                "vfs/queue" => Ok(serde_json::json!({"queue": []})),
                "core/stats" => Ok(serde_json::json!({"errors": 0})),
                "operations/stat" => Ok(serde_json::json!({})),
                _ => panic!("unexpected method"),
            }
        }
    }
    let health = health::snapshot(
        &Routes,
        cloudflare_disk::config::CryptConfig::REMOTE,
        true,
        true,
        100,
        10,
        1000,
    )
    .unwrap();
    assert!(health.drained() && health.backend_reachable);
}

#[test]
fn exclusive_lock_and_stable_recovery_flags_preserve_dirty_cache() {
    let root = tempfile::tempdir().unwrap();
    let p = profile(root.path());
    initialize(&p, &secrets()).unwrap();
    fs::write(p.cache_dir.join("dirty"), "unuploaded").unwrap();
    let lock = InstanceLock::acquire(&p.state_dir).unwrap();
    assert!(InstanceLock::acquire(&p.state_dir).is_err());
    let args = gateway::mount_args(&p);
    assert_eq!(args, gateway::mount_args(&p));
    assert!(args.windows(2).any(|v| v == ["--vfs-cache-mode", "full"]));
    for (flag, bytes) in [
        ("--vfs-cache-max-size", p.cache_target_bytes),
        ("--vfs-cache-min-free-space", p.min_free_bytes),
    ] {
        assert!(args
            .windows(2)
            .any(|v| v[0] == flag && v[1] == format!("{bytes}B")));
    }
    assert!(!args.join(" ").contains(&secrets().secret_access_key));
    drop(lock);
    let _restarted = InstanceLock::acquire(&p.state_dir).unwrap();
    assert_eq!(
        fs::read_to_string(p.cache_dir.join("dirty")).unwrap(),
        "unuploaded"
    );
}
#[test]
fn localhost_control_authentication_and_http_failure() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = vec![0; 4096];
        let n = stream.read(&mut request).unwrap();
        let request = String::from_utf8_lossy(&request[..n]);
        assert!(request.contains("POST /core/version"));
        assert!(request.contains("Authorization: Basic Z2F0ZXdheTpwYXNz"));
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 21\r\nConnection: close\r\n\r\n{\"version\":\"v1.70.0\"}").unwrap();
    });
    let control = health::LocalControl::new(port, "pass");
    assert_eq!(
        control.call("core/version", json!({})).unwrap()["version"],
        "v1.70.0"
    );
    server.join().unwrap();
    assert!(control.call("core/version", json!({})).is_err());
}

#[test]
fn disk_pressure_and_unknown_telemetry_are_not_silent_success() {
    struct Override {
        method: &'static str,
        value: Value,
    }
    impl Control for Override {
        fn call(&self, method: &str, body: Value) -> anyhow::Result<Value> {
            if method == self.method {
                Ok(self.value.clone())
            } else {
                FakeControl {
                    pending: false,
                    offline: false,
                    missing_queue: false,
                }
                .call(method, body)
            }
        }
    }
    let base = FakeControl {
        pending: false,
        offline: false,
        missing_queue: false,
    };
    for (available, target, pressure) in [(10, 101, false), (9, 101, true), (10, 100, true)] {
        let h = health::snapshot(&base, "r2:test", true, true, available, 10, target).unwrap();
        assert_eq!(h.cache_pressure, pressure);
    }
    let mut stats = base.call("vfs/stats", json!({})).unwrap();
    stats["diskCache"]["outOfSpace"] = json!(true);
    stats["diskCache"]["erroredFiles"] = json!(1);
    let control = Override {
        method: "vfs/stats",
        value: stats.clone(),
    };
    let h = health::snapshot(&control, "r2:test", true, true, 1000, 10, 500).unwrap();
    assert!(h.cache_pressure && !h.drained());
    for field in [
        "outOfSpace",
        "uploadsQueued",
        "uploadsInProgress",
        "erroredFiles",
        "bytesUsed",
    ] {
        let mut broken = stats.clone();
        broken["diskCache"].as_object_mut().unwrap().remove(field);
        let control = Override {
            method: "vfs/stats",
            value: broken,
        };
        assert!(health::snapshot(&control, "r2:test", true, true, 1000, 10, 500).is_err());
    }
    for value in [json!({}), json!({"queue":null}), json!({"queue":[{}]})] {
        let control = Override {
            method: "vfs/queue",
            value,
        };
        assert!(health::snapshot(&control, "r2:test", true, true, 1000, 10, 500).is_err());
    }
    let control = Override {
        method: "vfs/queue",
        value: json!({"queue":[{"tries":1}]}),
    };
    let h = health::snapshot(&control, "r2:test", true, true, 1000, 10, 500).unwrap();
    assert_eq!(
        h.pending_uploads, 1,
        "queue wins over lagging zero counters"
    );
    assert!(!h.drained());
}

#[test]
fn local_drain_is_not_independent_remote_durability() {
    let control = FakeControl {
        pending: false,
        offline: true,
        missing_queue: false,
    };
    let h = health::snapshot(&control, "r2:test", true, true, 1000, 10, 500).unwrap();
    // drained() is a local shutdown predicate, not a successful cloud GET.
    assert!(h.drained());
    assert!(!h.backend_reachable);
    for field in 0..5 {
        let mut h = telemetry(false);
        match field {
            0 => h.process_alive = false,
            1 => h.mount_ready = false,
            2 => h.pending_uploads = 1,
            3 => h.error_uploads = 1,
            _ => h.retrying_uploads = 1,
        }
        assert!(!h.drained());
    }
}

#[test]
fn live_harness_requires_opt_in_and_embedded_python_compiles() {
    use std::io::Write;
    use std::process::Stdio;
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/smb_roundtrip.sh");
    let output = Command::new("bash")
        .arg(&script)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(77));
    assert!(String::from_utf8_lossy(&output.stderr).contains("BLOCKED"));
    assert!(Command::new("bash")
        .arg("-n")
        .arg(&script)
        .status()
        .unwrap()
        .success());
    let smoke = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/docker_smoke.py");
    let output = Command::new("python3")
        .args([
            "-I",
            "-c",
            "import runpy, sys; reader = runpy.run_path(sys.argv[1])['CryptReader'];\ntry: reader({}, {})\nexcept AssertionError: pass\nelse: raise AssertionError('missing opt-in accepted')",
        ])
        .arg(smoke)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let source = fs::read_to_string(script).unwrap();
    let python = source
        .split("<<'PY'\n")
        .nth(1)
        .unwrap()
        .strip_suffix("PY\n")
        .unwrap();
    let mut child = Command::new("python3")
        .args([
            "-c",
            "import sys; compile(sys.stdin.read(), '<harness>', 'exec')",
        ])
        .stdin(Stdio::piped())
        .spawn()
        .expect("python3 required for offline harness syntax verification");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(python.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
}
