# Third-party components

Generated archives include `SBOM.json` for the Linux-resolved Cargo.lock dependencies and copies
of each crate's packaged license/notice files under `third-party/`. This is a
dependency inventory, including build-time crates; it is not a
statement that every listed crate is linked for Linux. The project license is
separate and remains pending.

The Rust standard library is Copyright The Rust Project Developers, distributed
under MIT OR Apache-2.0. Generated packages include the corresponding Rust license
texts. Linux libc is dynamically linked and supplied by the host; glibc is
LGPL-2.1-or-later. The release does not bundle libc or host daemons.

Runtime tools are obtained separately from their upstream/distro packages:

| Component | Upstream license | Distribution here |
| --- | --- | --- |
| rclone | MIT | Downloaded separately; checksum-pinned 1.70.3 option |
| Samba | GPL-3.0-or-later (component-specific exceptions apply) | System package |
| cryptsetup | GPL-2.0-or-later / LGPL-2.1-or-later components | System package |
| FUSE3 | GPL-2.0 / LGPL-2.1 components | System package |
| e2fsprogs | GPL/LGPL/BSD component licenses | System package |
| util-linux | GPL/LGPL/BSD component licenses | System package |
| nftables | GPL-2.0-or-later | System package |
| GnuPG | GPL-3.0-or-later | System package |
| systemd | LGPL-2.1-or-later and component licenses | Existing host |
| Python | PSF license | Existing host |

Consult the installed packages' copyright files for exact per-component terms.
The installer does not redistribute their executables in the candidate archive.

The pinned rclone Linux amd64 archive hash was obtained from the upstream GitHub
release asset digest and verified against the downloaded bytes. Upstream:
https://github.com/rclone/rclone/releases/tag/v1.70.3 .
