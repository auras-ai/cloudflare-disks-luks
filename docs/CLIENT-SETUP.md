# Client setup session

## Have ready

- A dedicated Ubuntu Server 24.04 x86_64 host, sudo access and Python 3.11+.
- A reserved/static private IPv4 address and the allowed client network CIDR.
  The supported default is a LAN subnet containing the gateway. A VPN must
  already be configured; the installer does not provision one.
- Persistent local ext4, XFS or Btrfs storage with free space for metadata, setup
  files and actual cached data. Setup calculates the metadata/workspace budget
  from the filesystem layout (roughly 0.5 GiB with default settings). The sparse
  image's 16 GiB capacity ceiling is not reserved; physical usage grows with data
  and filesystem/encryption overhead. Deleted cache blocks are reclaimed
  automatically. Keep free host space available for expected writes, including
  during an Internet outage. Never shrink the image.
- Cloudflare R2 enabled/billing configured, the 32-character account ID and a
  new bucket name. The default/global R2 jurisdiction is supported; jurisdiction-
  specific endpoints are not supported by this candidate.
- A password manager for three separate passwords: local LUKS unlock, client SMB
  access, and encrypted recovery-archive access. Crypt file keys are generated.
- Independent protected storage for the exported recovery archive.

Existing `r2disk` accounts, gateway storage, installed gateway files or occupied
TCP 445/5572 are refused. Use a clean gateway instead of replacing another service.

## Cloudflare credential options

### Automatic: create bucket and object credential

Create a short-lived bootstrap API token scoped to the chosen account with:

- **Workers R2 Storage Write**
- **Account API Tokens Write**

Account policy must permit granting **Workers R2 Storage Bucket Item Read** and
**Workers R2 Storage Bucket Item Write**. The permission-group endpoint checks
selectability and token creation performs Cloudflare's authoritative check.

The installer prompts privately for this token, discovers permission IDs,
creates a Standard-storage bucket, confirms r2.dev is disabled and no custom
domains exist, then creates `cloudflare-disk-<installation-id>` restricted to
Object Read & Write on that bucket. Its one-time value is converted to S3
credentials and saved only on encrypted storage. The bootstrap token is not saved.

Revoke the bootstrap token after a successful session. Retain the generated
bucket-scoped application token. No public domain, Worker, DNS record or cloud VM
is needed.

### Manual: use a dashboard-created bucket and S3 credential

Create a private bucket and an **Object Read & Write** credential scoped only to
that bucket. Choose `manual` during setup. Enter the **Access Key ID** and
**Secret Access Key** when prompted; a bearer API token is not an S3 credential.
Public access, lifecycle rules and exclusive ownership must be checked in the
dashboard. The installer still refuses a nonempty destination prefix.

References: [R2 tokens](https://developers.cloudflare.com/r2/api/tokens/),
[account tokens](https://developers.cloudflare.com/api/resources/accounts/subresources/tokens/methods/create/).

## Run the session

1. Verify the downloaded archive against the release's `SHA256SUMS`.
2. Extract into a trusted directory and run `sudo ./setup install --install-deps`.
   Package automation targets Ubuntu 24.04. On other systemd Linux distributions,
   install dependencies from the operations guide first and omit `--install-deps`.
3. Enter account/bucket, choose an interface, allowed subnet and local capacity limit.
4. Confirm the displayed plan. Choose the LUKS and SMB passwords in hidden prompts.
   The SMB password is 12–128 bytes, without control characters or leading/trailing
   whitespace; LUKS/recovery passphrases need at least 16 bytes.
5. Provide the Cloudflare bootstrap token or S3 credentials in the terminal.
6. Wait for the encrypted SMB/R2 test. It writes and removes a random 2 MiB test
   file and verifies it through a separate reader using the recovery keys.
7. Select an absolute filename for the encrypted recovery export and enter its
   separate passphrase. The default output is under `/root`. Use `sudo cp` to
   copy it to independent offline storage; preserve private permissions.
8. Connect a real client and perform the checks below. Revoke the bootstrap token.

Setup uses `/var/lib/cloudflare-disk/local.luks`, `/srv/r2-disk`, the Unix account
`r2disk` and the share `cloud`. The gateway is not automatically unlocked at boot.
No passwords appear in the printed handoff or command arguments.

## If interrupted

Run `sudo ./setup resume` from the **same release bundle**. Completed work is
checked and reused. You may need the existing LUKS passphrase or bootstrap token.

- **Bucket creation response lost:** inspect the named bucket in Cloudflare, then
  confirm its name in the resumed session. Public access still fails validation.
- **Token creation response lost before credentials were saved:** the journal
  records the exact token name. Revoke that token in Cloudflare, create a new
  bucket-scoped S3 credential, and run `sudo ./setup resume --import-r2`.
  The installer never blindly retries a token-creation POST.
- **Formatting interrupted or UUID differs:** stop and inspect the image. The
  installer does not reformat uncertain storage. See the operations guide.
- **Export interrupted:** the service may already be running; resume completes
  the encrypted export without changing the gateway's keys.

## Client handoff

Record in the client's password manager:

- Gateway address and Windows/macOS SMB connection path printed by setup.
- SMB username `r2disk` and password; gateway administrator contact.
- LUKS passphrase and reboot unlock procedure.
- Recovery archive location and its passphrase, stored separately.
- Cloudflare account, bucket and generated token name from the setup journal.

On **each client platform**: connect, create a document, save/close/reopen,
rename, copy a larger file, verify its bytes and delete the test files. Test
reconnection after a controlled clean gateway stop/start. Record results; the
Linux command-line smoke does not establish Windows/macOS acceptance.

The client needs SMB credentials only; never distribute Cloudflare or crypt keys
to desktop clients. A single shared SMB account provides no per-person ACLs.
