//! Single Linux gateway. A second gateway or external bucket writer is unsupported.
//! The instance lock is local only, never a distributed bucket lock.
pub mod gateway;
pub mod health;
pub mod samba;
#[cfg(not(target_os = "linux"))]
compile_error!("cloudflare-disk requires Linux");

pub mod config;
