use cloudflare_disk::{config::reject_nested_mounts, gateway};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    path::Path,
    process::Command,
};

#[test]
fn nested_mounts_fail_closed_without_rejecting_sibling_fuse() {
    let paths = [Path::new("/storage/state"), Path::new("/storage/cache")];
    for target in [
        "state",
        "cache",
        "state/tmp",
        "state/tmp/deep",
        "cache/vfs/deep",
    ] {
        for device in ["0:42", "253:0"] {
            let row = format!("43 42 {device} / /storage/{target} rw - ext4 /dev/test rw");
            assert!(reject_nested_mounts(&paths, &row).is_err());
        }
    }
    for target in ["mount", "state-other", "cache-other/sub"] {
        let row = format!("43 42 0:42 / /storage/{target} rw - fuse.rclone crypt: rw");
        reject_nested_mounts(&paths, &row).unwrap();
    }
    assert!(reject_nested_mounts(
        &[Path::new("/storage/my state")],
        "43 42 0:42 / /storage/my\\040state/tmp rw - tmpfs tmpfs rw"
    )
    .is_err());
}

#[test]
fn cli_exposes_explicit_initialization_and_real_serve_preflight() {
    let binary = env!("CARGO_BIN_EXE_cloudflare-disk");
    let help = Command::new(binary).arg("--help").output().unwrap();
    assert!(String::from_utf8_lossy(&help.stdout).contains("initialize-destination"));
    assert!(String::from_utf8_lossy(&help.stdout).contains("verify-destination"));
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("profile.toml");
    let mut profile: cloudflare_disk::config::Profile =
        toml::from_str(include_str!("../config/example.toml")).unwrap();
    profile.state_dir = root.path().join("state");
    profile.cache_dir = root.path().join("cache");
    profile.mount_dir = root.path().join("mount");
    fs::write(&config, toml::to_string(&profile).unwrap()).unwrap();
    for action in ["serve", "initialize-destination", "verify-destination"] {
        let result = Command::new(binary)
            .args([action, "--config"])
            .arg(&config)
            .output()
            .unwrap();
        assert!(!result.status.success());
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(!error.contains("serving is disabled"), "{error}");
        assert!(
            error.contains("r2disk") || error.contains("encrypted storage mount"),
            "{error}"
        );
    }
}

#[test]
fn smb_private_address_binding_is_explicit_and_backwards_compatible() {
    let root = tempfile::tempdir().unwrap();
    let mut profile: cloudflare_disk::config::Profile =
        toml::from_str(include_str!("../config/example.toml")).unwrap();
    profile.state_dir = root.path().join("state");
    profile.cache_dir = root.path().join("cache");
    profile.mount_dir = root.path().join("mount");
    profile.listen_address = None;
    assert!(cloudflare_disk::samba::configuration(&profile)
        .unwrap()
        .contains("interfaces = enp1s0\n"));
    for address in ["192.168.50.2", "10.4.5.6", "172.16.0.2", "100.64.10.20"] {
        profile.listen_address = Some(address.parse().unwrap());
        let text = cloudflare_disk::samba::configuration(&profile).unwrap();
        assert!(text.contains(&format!("interfaces = {address}/32\n")));
        assert!(!text.contains("interfaces = enp1s0"));
    }
    for address in [
        "0.0.0.0",
        "127.0.0.1",
        "1.1.1.1",
        "169.254.1.2",
        "100.128.0.1",
        "224.0.0.1",
    ] {
        profile.listen_address = Some(address.parse().unwrap());
        assert!(cloudflare_disk::samba::configuration(&profile).is_err());
    }
}

#[test]
fn public_status_routes_all_remote_requests_through_crypt() {
    let root = tempfile::tempdir().unwrap();
    let mut profile: cloudflare_disk::config::Profile =
        toml::from_str(include_str!("../config/example.toml")).unwrap();
    profile.state_dir = root.path().join("state");
    profile.cache_dir = root.path().join("cache");
    profile.mount_dir = root.path().join("mount");
    for path in [&profile.state_dir, &profile.cache_dir, &profile.mount_dir] {
        fs::create_dir(path).unwrap();
    }
    let password = profile.state_dir.join("control.password");
    fs::write(&password, "test-password").unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(password, fs::Permissions::from_mode(0o600)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    profile.control_port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        for expected in [
            "core/version",
            "rc/list",
            "vfs/stats",
            "vfs/queue",
            "core/stats",
            "operations/stat",
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.starts_with(&format!("POST /{expected} ")));
            let mut length = 0;
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            if expected.starts_with("vfs/") || expected == "operations/stat" {
                assert_eq!(body["fs"], "crypt:");
            }
            let response = match expected {
                "core/version" => r#"{"version":"v1.70.0"}"#,
                "rc/list" => {
                    r#"{"commands":[{"Path":"vfs/stats"},{"Path":"vfs/queue"},{"Path":"operations/stat"},{"Path":"core/stats"}]}"#
                }
                "vfs/stats" => {
                    r#"{"diskCache":{"bytesUsed":0,"uploadsQueued":0,"uploadsInProgress":0,"erroredFiles":0,"outOfSpace":false},"inUse":0}"#
                }
                "vfs/queue" => r#"{"queue":[]}"#,
                "core/stats" => r#"{"errors":0}"#,
                _ => "{}",
            };
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
        }
    });
    let health = gateway::status(&profile).unwrap();
    assert!(health.backend_reachable);
    assert_eq!(health.pending_uploads, 0);
    server.join().unwrap();
}
