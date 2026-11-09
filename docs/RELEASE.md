# Release preparation and publication

## Candidate status: 0.2.0-rc.1

Included: guided setup/resume, optional Ubuntu dependencies, Cloudflare create or
manual credential import, bounded LUKS2 storage, private SMB address binding,
systemd/firewall integration, independent encrypted SMB/R2 verification, GPG
recovery export, source/binary packaging, dependency notices, checksums and CI.

Evidence and limits:

- The preceding host-managed gateway passed a live encrypted 2 MiB SMB
  create/read/rename/delete test, raw R2 ciphertext inspection and independent
  recovery-key decrypt on 2026-11-08. Test objects were removed and telemetry
  reported zero pending/error/retrying transfers. This is earlier gateway
  evidence, not a fresh-client installer acceptance result.
- Automated Rust tests cover validation, storage provenance, private state,
  SMB configuration, lifecycle/control behavior and CLI gates.
- Python tests cover API/policy contracts, interrupted setup boundaries,
  refusing foreign storage, preserving keys, sparse allocation/discard policy and
  real ext4 metadata sizing/low-space recovery,
  ambiguous token creation, redaction, encrypted recovery export and release
  allowlist/content verification.
- Preparation checks on 2026-11-08 passed: **28 Rust tests**, **23 Python tests**,
  Rust formatting and strict all-targets Clippy, workflow/Python/shell syntax,
  real GPG export/decrypt, and nftables syntax validation in an isolated network
  namespace, plus disposable non-root LUKS2 format/signature/header verification.
  The portable Rust 1.98.1 build executed successfully in Debian
  Bookworm; the upstream pinned rclone archive hash was verified by download.
- The new guided installer has **not yet completed end-to-end on a clean client
  VM**, nor a reboot/unlock acceptance run. Its Cloudflare automatic provisioning
  has contract tests but has not created another live account/bucket during this
  release-preparation task.
- Crash, power loss, outage, disk-pressure/storage-loss and Windows/macOS client
  acceptance remain outstanding. Label distributions as a release candidate.

## Build and check

Use Rust 1.98.1 (the pinned release builder), Python 3.11+, Docker and an x86_64
Linux host. Normal development can use a compatible newer Rust toolchain.

```sh
cargo fetch --locked
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
python3 -B -m unittest discover -s tests -p 'test_*.py' -v
bash scripts/portable-build.sh
python3 -B scripts/release.py --binary target/portable/cloudflare-disk
python3 -B scripts/release.py --verify dist
```

Fetching first also populates platform-specific dependency metadata used by the
offline notice generator. The locked dependency graph requires Rust 1.88 or newer;
the release is built and checked with 1.98.1 rather than asserting an older MSRV test.

The portable builder uses a pinned Rust/Bookworm image with glibc 2.36 and only
copies the Rust source/manifests into a temporary build context. It does not mount
the working checkout or client secrets into the container. The package checker
rejects binaries requiring newer glibc than 2.36. CI also executes the binary
in Debian Bookworm. No Docker privileges are required by the delivered gateway.

Set `CLOUDFLARE_DISK_OFFLINE_BUILD=1` to seed the build from the local Cargo
registry cache (never Cargo credentials/config). Both builds use `Cargo.lock`.

The packager creates:

- `dist/cloudflare-disk-0.2.0-rc.1-source.tar.gz`
- `dist/cloudflare-disk-0.2.0-rc.1-linux-x86_64-gnu.tar.gz`
- `dist/SHA256SUMS`

Every archive contains `RELEASE-MANIFEST.json` with hashes of all payload files,
`SBOM.json` with Linux-resolved locked Rust dependency versions/checksums/licenses, and license
texts under `third-party/`. Files are selected by an explicit allowlist. Secrets,
runtime/cache/image files, local history, `.empryo`, `target`, recovery archives
and historical local deployment notes are excluded. Files are stored as ordinary
regular files with deterministic ownership and timestamps; links are rejected.
Checksums detect corruption; authenticate the eventual release origin separately.

## Before the first tagged release

The source repository is [auras-ai/cloudflare-disks-luks](https://github.com/auras-ai/cloudflare-disks-luks).
Choose the client-approved license. Add `LICENSE`, set
`package.license` to its SPDX expression in Cargo.toml, and update README's license
section. The current `LICENSE-PENDING.md` is a preparation marker, not an open-source
license. Dependency licenses do not grant a license to this project.

The repository tracks the reviewed source allowlist. Do not `git add .` in a
deployment checkout containing credentials.
The `.github` workflows are included in source releases. CI has no Cloudflare
secrets and never provisions real services. Rebuild after setting the license;
public packaging/publishing refuses a candidate with pending licensing.

Then tag the verified source as `v0.2.0-rc.1` and use the manual **Release**
workflow, or run `scripts/publish.py --repo auras-ai/cloudflare-disks-luks --tag v0.2.0-rc.1 --publish`
from the clean tagged checkout with authenticated GitHub CLI. The script checks
the license, clean checkout, exact tag and artifact manifests, then creates a
GitHub prerelease. Tagged release archives have not yet been published.

## Acceptance before broad client rollout

On a disposable clean Ubuntu gateway with a dedicated R2 bucket, record:

1. Full guided automatic setup and manual-credential setup; verify private bucket
   access and denied access outside the bucket.
2. Interrupt/resume after allocation, LUKS format, token response and profile
   writes; assert original identities/keys and no second format/token request.
3. Clean stop/reboot/manual unlock; verify mounts, private bindings, firewall
   scope, clean telemetry and independent file bytes.
4. Windows and macOS create/read/rename/delete/reconnect tests, including large
   files and naming conventions used by the client.
5. Controlled Internet outage, cache pressure, child crash and storage-loss tests
   on disposable data; verify retained cache and fail-closed writer behavior.
6. Restore/decrypt the exported recovery archive on a separate machine and read
   uploaded data without the gateway cache. Test LUKS header recovery on a clone.
7. Measure the sparse backing file's allocated blocks before/after cache writes,
   deletion/eviction and TRIM. Repeat after reboot/unlock; verify original file
   bytes, persisted discard passthrough and the systemd mount's `discard` option.

The historical Docker fault hook intentionally refuses destructive testing and
is not a substitute for these host-managed encrypted-storage tests.
