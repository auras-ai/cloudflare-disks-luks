# Changelog

## 0.2.0-rc.1

- Guided existing-Linux-gateway installation and durable resume journal.
- Private R2 bucket/account-token provisioning, plus manual S3 credential import.
- New preallocated LUKS2 image, UUID-checked reuse and desktop auto-unlock exclusion.
- Dedicated service user, systemd units, private IPv4 binding and scoped SMB firewall.
- Independent recovery-key readback test and encrypted GPG recovery export.
- Source/binary release archives, checksums, dependency notices and CI/publishing tools.
- Operator/client documentation and explicit outstanding acceptance coverage.

Retains single-writer gateway semantics and persistent dirty-cache recovery.
No automatic cloud VM provisioning, public SMB exposure or unattended unlock.
