//! Administrator setup: create the dedicated `r2disk` Unix account, initialize/run
//! this gateway as that account, install Samba >= 4.19 (including pdbedit/testparm),
//! and grant smbd permission to bind TCP 445 (e.g. a narrowly scoped systemd
//! ambient CAP_NET_BIND_SERVICE). Never run the gateway as root. No useradd,
//! sudo, firewall, /etc/samba or /etc/fuse.conf changes are performed here.
//!
//! All clients MUST use this one gateway for Samba's shared locks. Independent
//! mounts/external bucket writers are unsupported. Case is preserved and lookup
//! is case-sensitive: avoid names differing only by case or Unicode normalization.
//! Windows reserved names, trailing dots/spaces and :*?<>| are not portable.
//! Finder metadata/resource forks and NTFS ACLs/streams are not promised; object
//! stores do not provide full NTFS/POSIX rename, directory or durability semantics.
//! Windows Explorer/macOS Finder live checks are required before platform claims.
use crate::config::{Profile, Secrets};
use anyhow::{ensure, Context, Result};
use std::{
    ffi::CStr,
    fs::{self, DirBuilder, File},
    io::Write,
    os::unix::{
        fs::{DirBuilderExt, MetadataExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

pub const SHARE_USER: &str = "r2disk";

pub fn check_identity() -> Result<()> {
    let uid = unsafe { libc::geteuid() };
    ensure!(uid != 0 && uid == unsafe { libc::getuid() }, "run as dedicated r2disk Unix user, not root/setuid; administrator must create account and grant smbd TCP 445 binding permission");
    let user = unsafe { libc::getpwuid(uid) };
    ensure!(!user.is_null(), "Unix account missing");
    ensure!(
        unsafe { CStr::from_ptr((*user).pw_name) }.to_bytes() == SHARE_USER.as_bytes(),
        "administrator must create r2disk; run gateway and FUSE as that user"
    );
    Ok(())
}

pub fn configuration(p: &Profile) -> Result<String> {
    p.validate()?;
    for path in [&p.state_dir, &p.mount_dir] {
        let text = path.to_str().context("non UTF-8 Samba path")?;
        ensure!(
            !text.chars().any(char::is_whitespace) && !text.contains('#'),
            "Samba paths must not contain whitespace or comment markers"
        );
    }
    let root = p.state_dir.join("samba");
    Ok(format!(
        "[global]\n\
server role = standalone server\n\
security = user\n\
server min protocol = SMB3_00\n\
server max protocol = SMB3\n\
server smb encrypt = required\n\
map to guest = Never\n\
restrict anonymous = 2\n\
null passwords = no\n\
interfaces = {interface}\n\
bind interfaces only = yes\n\
smb ports = 445\n\
disable netbios = yes\n\
load printers = no\n\
printing = bsd\n\
printcap name = /dev/null\n\
dns proxy = no\n\
usershare max shares = 0\n\
allow insecure wide links = no\n\
passdb backend = tdbsam:{root}/private/passdb.tdb\n\
private dir = {root}/private\n\
pid directory = {root}/pid\n\
lock directory = {root}/lock\n\
state directory = {root}/state\n\
cache directory = {root}/cache\n\
ncalrpc dir = {root}/ncalrpc\n\
log file = {root}/log.smbd\n\
[{}]\n\
path = {}\n\
valid users = r2disk\n\
guest ok = no\n\
guest only = no\n\
read only = no\n\
browseable = yes\n\
smb encrypt = required\n\
wide links = no\n\
follow symlinks = no\n\
locking = yes\n\
strict locking = yes\n\
case sensitive = yes\n\
preserve case = yes\n\
short preserve case = yes\n\
mangled names = no\n\
store dos attributes = no\n\
ea support = no\n",
        p.share,
        p.mount_dir.display(),
        interface = p
            .listen_address
            .map(|address| format!("{address}/32"))
            .unwrap_or_else(|| p.interface.clone()),
        root = root.display()
    ))
}

fn private_dir(path: &Path) -> Result<()> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o777 == 0o700,
        "unsafe Samba directory"
    );
    Ok(())
}

/// Runs testparm before provisioning the isolated password DB; password travels
/// only over a pipe, never argv/environment/logs. No host password database edits.
pub fn prepare(p: &Profile, secrets: &Secrets) -> Result<PathBuf> {
    let text = configuration(p)?;
    secrets.validate()?;
    private_dir(&p.state_dir)?;
    let root = p.state_dir.join("samba");
    private_dir(&root)?;
    for name in ["private", "pid", "lock", "state", "cache", "ncalrpc"] {
        private_dir(&root.join(name))?;
    }
    let config = root.join("smb.conf");
    let mut temp = tempfile::NamedTempFile::new_in(&root)?;
    temp.write_all(text.as_bytes())?;
    temp.as_file().sync_all()?;
    temp.persist(&config)?;
    ensure!(
        Command::new("testparm")
            .args(["-s", "--suppress-prompt"])
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .context("install testparm")?
            .success(),
        "testparm rejected dedicated Samba configuration"
    );
    let mut child = Command::new("pdbedit")
        .args(["--configfile"])
        .arg(&config)
        .args(["--create", "--user", SHARE_USER, "--password-from-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("install pdbedit; no system account will be created")?;
    let write = (|| -> Result<()> {
        let mut input = child.stdin.take().context("password pipe missing")?;
        writeln!(input, "{}\n{}", secrets.smb_password, secrets.smb_password)?;
        Ok(())
    })();
    let status = child.wait()?;
    write?;
    ensure!(
        status.success(),
        "pdbedit failed; administrator must create r2disk and permit dedicated database access"
    );
    Ok(config)
}

pub struct Samba {
    child: Child,
    stopped: bool,
}
impl Samba {
    pub fn start(config: &Path) -> Result<Self> {
        let child = Command::new("smbd")
            .args(["--foreground", "--no-process-group", "--configfile"])
            .arg(config)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("start smbd; administrator must permit TCP 445 binding")?;
        Ok(Self {
            child,
            stopped: false,
        })
    }
    pub fn alive(&mut self) -> Result<bool> {
        Ok(self.child.try_wait()?.is_none())
    }
    pub fn stop(&mut self) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        // Kill the entire private process group, including per-client workers,
        // before mount teardown/drain; stopping only the listener is insufficient.
        let rc = unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
        ensure!(
            rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
            "cannot stop Samba workers"
        );
        self.child.wait()?;
        self.stopped = true;
        Ok(())
    }
}
impl Drop for Samba {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Deny access to the *underlying* directory before allowing SMB startup. This
/// descriptor was opened before FUSE mounted: fchmod cannot affect the mounted
/// root. Non-root SMB workers cannot serve the bare directory even between polls.
pub fn seal_underlay(directory: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    directory.set_permissions(fs::Permissions::from_mode(0o000))?;
    Ok(())
}
