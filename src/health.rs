//! Bounded, authenticated, loopback-only rclone RC. Unknown telemetry fails closed.
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Serialize;
use serde_json::{json, Value};
use std::{io::Read, time::Duration};

pub trait Control {
    fn call(&self, method: &str, body: Value) -> Result<Value>;
}

pub struct LocalControl {
    port: u16,
    authorization: String,
    agent: ureq::Agent,
}
impl LocalControl {
    pub fn new(port: u16, password: &str) -> Self {
        Self {
            port,
            authorization: format!("Basic {}", STANDARD.encode(format!("gateway:{password}"))),
            agent: ureq::AgentBuilder::new()
                .redirects(0)
                .timeout(Duration::from_secs(2))
                .build(),
        }
    }
}
impl Control for LocalControl {
    fn call(&self, method: &str, body: Value) -> Result<Value> {
        ensure!(
            method
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'/'),
            "invalid RC method"
        );
        let response = self
            .agent
            .post(&format!("http://127.0.0.1:{}/{method}", self.port))
            .set("Authorization", &self.authorization)
            .send_json(body)
            .map_err(|_| anyhow::anyhow!("rclone control request failed: {method}"))?;
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1024 * 1024, "RC response exceeds limit");
        serde_json::from_slice(&bytes).context("invalid RC JSON")
    }
}

/// Check the actual running binary, not an assumed API based only on its version.
pub fn verify(control: &impl Control) -> Result<String> {
    let version = control.call("core/version", json!({}))?;
    let version = version["version"]
        .as_str()
        .context("missing rclone version")?;
    let parts: Vec<u32> = version
        .trim_start_matches('v')
        .split('.')
        .take(2)
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        parts.len() == 2 && (parts[0], parts[1]) >= (1, 70),
        "rclone >= 1.70 required (verified vfs/queue API)"
    );
    let methods = control.call("rc/list", json!({}))?;
    let methods = methods["commands"]
        .as_array()
        .context("missing RC command list")?;
    for required in ["vfs/stats", "vfs/queue", "operations/stat", "core/stats"] {
        ensure!(
            methods.iter().any(|m| m["Path"] == required),
            "rclone lacks required endpoint {required}"
        );
    }
    Ok(version.to_owned())
}

#[derive(Debug, Serialize)]
pub struct Health {
    pub process_alive: bool,
    pub mount_ready: bool,
    pub backend_reachable: bool,
    pub cache_pressure: bool,
    pub pending_uploads: u64,
    pub error_uploads: u64,
    pub retrying_uploads: usize,
    pub transfer_errors: u64,
    pub cache_bytes: u64,
    pub available_bytes: u64,
    pub in_use: u64,
}
impl Health {
    pub fn drained(&self) -> bool {
        self.process_alive
            && self.mount_ready
            && self.pending_uploads == 0
            && self.error_uploads == 0
            && self.retrying_uploads == 0
    }
}
fn number(value: &Value, key: &str) -> Result<u64> {
    value[key]
        .as_u64()
        .with_context(|| format!("missing RC counter {key}"))
}
pub fn snapshot(
    control: &impl Control,
    remote: &str,
    alive: bool,
    mounted: bool,
    available: u64,
    minimum: u64,
    target: u64,
) -> Result<Health> {
    let stats = control.call("vfs/stats", json!({"fs": remote}))?;
    let queue = control.call("vfs/queue", json!({"fs": remote}))?;
    let queue = queue["queue"].as_array().context("missing upload queue")?;
    let disk = &stats["diskCache"];
    let core = control.call("core/stats", json!({}))?;
    let cache_bytes = number(disk, "bytesUsed")?;
    let pending = number(disk, "uploadsQueued")? + number(disk, "uploadsInProgress")?;
    let errors = number(disk, "erroredFiles")?;
    let out_of_space = disk["outOfSpace"]
        .as_bool()
        .context("missing cache pressure flag")?;
    let mut retrying = 0;
    for item in queue {
        if number(item, "tries")? > 1 {
            retrying += 1;
        }
    }
    Ok(Health {
        process_alive: alive,
        mount_ready: mounted,
        backend_reachable: control
            .call("operations/stat", json!({"fs": remote, "remote": ""}))
            .is_ok(),
        cache_pressure: out_of_space || available < minimum || cache_bytes >= target,
        pending_uploads: pending.max(queue.len() as u64),
        error_uploads: errors,
        retrying_uploads: retrying,
        transfer_errors: number(&core, "errors")?,
        cache_bytes,
        available_bytes: available,
        in_use: number(&stats, "inUse")?,
    })
}
