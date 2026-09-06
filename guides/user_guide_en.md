# Kapsaro User Guide

## Table of Contents

1. [Introduction and Security Assumptions](#1-introduction-and-security-assumptions)
2. [Installation](#2-installation)
3. [Creating and Joining a Workspace](#3-creating-and-joining-a-workspace)
4. [KV Operations](#4-kv-operations)
5. [File Encryption and Decryption](#5-file-encryption-and-decryption)
6. [Member Management](#6-member-management)
7. [Key Management and Rotation](#7-key-management-and-rotation)
8. [CI/CD Integration](#8-cicd-integration)
9. [Diagnostics](#9-diagnostics)
10. [Troubleshooting and FAQ](#10-troubleshooting-and-faq)
11. [Command and Configuration Reference](#11-command-and-configuration-reference)
12. [Glossary](#12-glossary)

---

<a id="1-introduction"></a>

## 1. Introduction and Security Assumptions

### What Is Kapsaro?

Kapsaro is an offline-first CLI for sharing database credentials, API tokens, and certificates as encrypted files in Git. It helps teams replace practices such as:

- Pasting credentials in plaintext into Slack, Teams, or email
- Leaving real secrets commented out inside `.env.example`
- Departing team members retaining access to shared passwords indefinitely

Kapsaro encrypts secrets before they enter Git and records changes with signatures and disclosure metadata. Revoking credentials at their issuing services remains a separate operational task.

### What Kapsaro Solves

- Encrypts `.env` values and files for sharing through Git
- Updates encrypted files' recipients when a member runs `rewrap` after membership changes
- Records removed recipients to help identify values that may need replacement
- Encrypts, decrypts, and verifies signatures locally; optional GitHub identity checks use the network

### What Kapsaro Does Not Solve

Authorized recipients can copy decrypted values. Kapsaro cannot recover those copies, revoke credentials at their issuing services, or protect secrets on a compromised endpoint. The [security assumptions below](#4-security-basics-for-users) describe the responsibilities that remain with the team.

---

<a id="2-what-to-know-before-you-start"></a>

### Understanding the High-Level Flow

The sharing workflow has three parts:

1. The team shares encrypted files and member public keys in the repository's `.kapsaro/` workspace.
2. Each member maintains a personal public/private keypair.
3. Existing members review new members and replacement keys through pull requests, then apply the approved changes with `rewrap`.

### The Git Workspace

The default workspace is the `.kapsaro/` directory at the repository root:

```
.kapsaro/
├── members/
│   ├── active/
│   └── incoming/
├── secrets/
└── config.toml
```

- `members/active/`: Public keys of currently approved team members
- `members/incoming/`: Public keys pending review or key rotation
- `secrets/`: Encrypted secret stores and files

> [!IMPORTANT]
> Commit `.kapsaro/` with the project. Keep it out of `.gitignore`.

### The Role of Public and Private Keys

Each member shares a public key and keeps the corresponding private key confidential. Kapsaro encrypts the contents with a symmetric key and protects that key separately for each recipient using public-key encryption. Members can therefore share encrypted data without distributing their private keys or maintaining a team master password.

Never share your private key. Someone who obtains it may decrypt files addressed to that key and sign as you. Keep private keys out of Git, chat, and unencrypted backups.

Public keys under `members/active/` and `members/incoming/` can be shared without exposing the private keys. Public key documents do reveal member identity metadata, however, so review that information before publishing a repository.

Before approving a key, verify that it belongs to the intended teammate. A public key alone establishes neither the owner's identity nor permission to receive secrets.

### How Members Are Activated

New members and rotated keys are initially placed in `members/incoming/`. They become authorized recipients only after an existing member reviews the pull request and executes `kapsaro rewrap`.

Use pull-request review to check the member's identity and need for access. Kapsaro applies the approved membership through `rewrap`; local key approvals record identity checks on each workstation. A valid signature proves neither real-world identity nor permission by itself.

### Core Formats

- kv-enc stores `.env`-style key-value pairs and supports updates to individual entries.
- file-enc encrypts a complete file, including certificates and binary data.

See [KV operations](#4-kv-operations) and [file operations](#5-file-encryption-and-decryption) for commands.

---

<a id="4-security-basics-for-users"></a>

### What Kapsaro Protects

Files created by Kapsaro use authenticated encryption and digital signatures. Under the cryptographic assumptions described in the [Security Design](security_design_en.md), their contents remain confidential to parties who lack the required keys and have not obtained the plaintext elsewhere.

### What Kapsaro Does Not Automatically Protect

- How authorized members handle secrets after decryption
- Copies, screenshots, or personal recollections of previously decrypted values
- Endpoints compromised by malware or stolen private keys

Removing a member preserves their access to any old ciphertext and plaintext they retained. Revoke and replace credentials they could access at the issuing services as part of offboarding.

### What Remains Visible as Plaintext Metadata

While Kapsaro cryptographically protects secret payloads and file contents, operational metadata remains visible in plaintext for auditing and synchronization:

- Key names in kv-enc stores
- Recipient lists (`member_handle` and `kid`)
- Signer `kid`
- Creation and modification timestamps
- Historical disclosure records

`kapsaro list` displays key names, while `kapsaro inspect` displays metadata and signature results without decrypting values. Disclosure records show prior recipient access, not whether anyone actually read a value. If key names, timestamps, or member identities are sensitive, restrict repository access or use separate workspaces.

### The Role of the SSH Key

Your Ed25519 SSH key protects your local Kapsaro private key and signs the attestation that binds a Kapsaro public key to that SSH key. The Kapsaro private key decrypts workspace data.

GitHub-backed online verification checks whether `attestation.pub`, the SSH public key in the attestation, is currently registered on the member's GitHub account. Removing that key from GitHub makes subsequent online checks fail. It does not revoke existing workspace access or erase local approvals.

### Operational Principles

- Never merge pull requests containing unfamiliar public keys
- Never share Kapsaro or SSH private keys
- If compromise is suspected, use a trusted workstation to replace affected SSH and Kapsaro keys, exclude compromised keys, rotate content keys, and revoke exposed credentials; follow [key management](#7-key-management-and-rotation)
- When using GitHub verification, remove decommissioned SSH keys from GitHub once migration completes

For architectural details, see the [Security Design](security_design_en.md).

---

<a id="5-installation"></a>

## 2. Installation

### Prerequisites

- An Ed25519 SSH key (`~/.ssh/id_ed25519`)
- An active SSH agent (recommended) or `ssh-keygen`

### Install via Homebrew (Recommended)

```bash
brew tap ebisawa/kapsaro
brew install kapsaro
```

### Install from Source

```bash
git clone https://github.com/ebisawa/kapsaro.git
cd kapsaro
cargo install --path .
```

After installation, verify the binary by running `kapsaro --help`.

### Verify SSH Agent Configuration

Kapsaro uses your SSH key to protect local private keys. Verify that your SSH agent is running and has your key loaded:

```bash
# Check loaded keys in ssh-agent
ssh-add -l

# If no keys are listed, load your Ed25519 key
ssh-add ~/.ssh/id_ed25519
```

> [!NOTE]
> Kapsaro strictly requires Ed25519 keys; legacy RSA keys are unsupported.

```bash
# Generate an Ed25519 key if you do not already have one
ssh-keygen -t ed25519 -C "your@email.com"
```

If you prefer not to use an SSH agent, Kapsaro can sign directly using `ssh-keygen`; see [Why is the SSH agent needed?](#q-why-is-the-ssh-agent-needed).

---

<a id="6-quick-start-team-leader"></a>

## 3. Creating and Joining a Workspace

### Create a Workspace

Follow these steps when setting up Kapsaro for your team for the first time.

#### Step 1: Prepare a Repository

Navigate to your target project repository:

```bash
# Navigate to an existing repository
cd /path/to/your-repo

# Or create a new repository
git init my-project
cd my-project
```

#### Step 2: Initialize the Workspace

```bash
kapsaro init --member-handle alice@example.com
```

Output:

```
Creating workspace .kapsaro/
  Created members/active/
  Created members/incoming/
  Created secrets/
Using SSH key: SHA256:xxxxx... (from ~/.ssh/id_ed25519)
SSH signature determinism: OK
Generated and activated key for 'alice@example.com':
  Key ID:   7M2Q-9D4R-1H8V-W6PK-T3XN-C5JY-2F9A-R8GD
  Expires:  2027-03-19T00:00:00Z
Added 'alice@example.com' to members/active/
```

`kapsaro init` performs these steps:

- Creates the `.kapsaro/` directory hierarchy
- Uses your local keypair or generates one in `~/.config/kapsaro/keys/` if needed
- Registers your public key at `.kapsaro/members/active/alice@example.com.json`

If the workspace already contains active members, `init` exits without changes. Use `kapsaro join` to submit a key to an existing workspace.

#### Step 3: Add Your First Secrets

The values below are examples. For real credentials, use [hidden standard input](#secret-input) to keep them out of shell history and process arguments.

```bash
# Add individual entries
kapsaro set DATABASE_URL "postgres://user:pass@localhost/mydb"
kapsaro set API_KEY "sk-your-api-key"

# Or bulk-import an existing .env file
kapsaro import .env
```

#### Step 4: Verify Secret Access

```bash
kapsaro list
kapsaro run -- true
```

`kapsaro list` verifies key names without printing values, and `kapsaro run -- true` verifies that decryption succeeds end-to-end without leaking secrets to the console.

#### Step 5: Commit to Git

```bash
git add .kapsaro/
git commit -m "Initialize kapsaro workspace"
```

#### Step 6: Onboard Team Members

Ask teammates to follow [Join a Workspace](#join-a-workspace). Review their pull requests and complete the [member addition procedure](#member-addition-git-workflow).

---

<a id="7-joining-as-a-new-member"></a>

### Join a Workspace

Follow these steps to join an existing team workspace.

#### Step 1: Clone the Repository

```bash
git clone <repo-url>
cd my-project
```

#### Step 2: Submit a Join Request

```bash
kapsaro join --member-handle bob@example.com
```

Output:

```
Using SSH key: SHA256:xxxxx... (from ~/.ssh/id_ed25519)
Generated and activated key for 'bob@example.com':
  Key ID:   9N4R-1H8V-W6PK-T3XN-C5JY-2F9A-R8GD-7M2Q
  Expires:  2027-03-19T00:00:00Z
Added 'bob@example.com' to members/incoming/

Ready! Create a PR to share your public key with the team.
```

`join` submits a key to an existing workspace. It uses your available local key or generates a keypair if needed, then places the public key in `members/incoming/`. Existing members also use it to submit replacement keys.

#### Step 3: Create a Pull Request

```bash
git checkout -b join/bob
git add .kapsaro/members/incoming/bob@example.com.json
git commit -m "Add bob to kapsaro (incoming)"
git push origin join/bob
```

Create a pull request on GitHub or your Git platform and request a review from existing members.

#### Step 4: Ask an Existing Member to Run rewrap

Once your PR is merged, an existing member executes the [shared completion procedure](#membership-completion) to rewrap encrypted files, commit the changes, and push them. Wait until this step is complete before proceeding.

#### Step 5: Verify Access and Trust Existing Members

```bash
# Verify working tree and pull the latest changes
git status --short
git pull --ff-only

# Review and approve existing members' public keys
kapsaro member verify --approve

# Verify decryption without printing secret values
kapsaro run -- true
```

When approving keys, verify the displayed handles and fingerprints. A successful `kapsaro run -- true` confirms access to the default store. Check each named store with `-n` and each standalone file with `decrypt` before declaring onboarding complete.

---

<a id="8-daily-usage-kv-store"></a>

## 4. KV Operations

### Adding and Updating Entries

```bash
# Basic usage in the default store
kapsaro set DATABASE_URL "postgres://user:pass@localhost/db"

# Store in named environments (-n option)
kapsaro set -n staging DATABASE_URL "postgres://user:pass@staging/db"
kapsaro set -n prod DATABASE_URL "postgres://user:pass@prod/db"
```

If no store is specified, secrets are saved to the `default` store (`.kapsaro/secrets/default.kvenc`).

<a id="workspace-sharing"></a>

Named stores (such as `dev`, `staging`, or `prod`) organize secrets for one workspace's members. They use the recipient group in `members/active/`; synchronize existing files with `rewrap` after membership changes. For a different access group, create a separate workspace with its own members, then select it explicitly:

```bash
kapsaro set --workspace .kapsaro-prod -n prod DATABASE_URL --stdin
kapsaro run --workspace .kapsaro-prod -n prod -- ./my-app
```

<a id="secret-input"></a>

Always enter sensitive passwords and tokens via `--stdin` to keep them out of command-line arguments and shell history files. To hide characters while typing in Bash:

```bash
(
  set -eu
  terminal_state=$(stty -g)
  trap 'stty "$terminal_state"' EXIT
  stty -echo
  kapsaro set SECRET_TOKEN --stdin
)
```

Type or paste the value, press Enter, and then press Ctrl+D to complete the input.

### Removing Entries

```bash
kapsaro unset OLD_KEY
kapsaro unset -n staging OLD_KEY
```

### Retrieving Entries

```bash
# Retrieve a single value
kapsaro get DATABASE_URL

# Output in KEY="VALUE" format
kapsaro get --with-key DATABASE_URL

# Retrieve all entries
kapsaro get --all
kapsaro get --all --with-key

# Retrieve from a named store
kapsaro get -n staging DATABASE_URL
```

### Listing Keys

```bash
# List key names without decrypting values
kapsaro list

# List keys from a named store
kapsaro list -n staging
```

`kapsaro list` verifies signatures and trust without decrypting values.

### Injecting Secrets into Application Commands

```bash
# Inject all secrets from the default store as environment variables
kapsaro run -- ./my-app

# Use a named store
kapsaro run -n staging -- ./my-app

# Pass multiple command arguments
kapsaro run -- python manage.py runserver
```

`kapsaro run` inherits the parent shell environment, strips any variables starting with `KAPSARO_`, and injects decrypted secrets last, overriding conflicting parent variables.

### Bulk Importing a `.env` File

```bash
# Import into the default store
kapsaro import .env

# Import into a named store
kapsaro import -n staging staging.env
```

Existing keys are overwritten with imported values.

---

<a id="9-file-encryption-and-decryption"></a>

## 5. File Encryption and Decryption

Use `encrypt` and `decrypt` for arbitrary files such as certificates, private keys, or binary archives.

### Encrypting Files

```bash
# Encrypt a file (produces <filename>.encrypted in the current directory)
kapsaro encrypt certs/ca.pem

# Specify an explicit output destination
kapsaro encrypt certs/ca.pem --out .kapsaro/secrets/ca.pem.encrypted

# Encrypt from stdin to a file
cat certs/ca.pem | kapsaro encrypt --stdin --out .kapsaro/secrets/ca.pem.encrypted

# Encrypt from stdin and emit file-enc JSON to stdout
cat certs/ca.pem | kapsaro encrypt --stdin --stdout > ca.pem.encrypted
```

Digital signatures are automatically attached during encryption.

### Decrypting Files

```bash
# Verify signature and decrypt to an output file
kapsaro decrypt ca.pem.encrypted --out certs/ca.pem

# Decrypt to stdout
kapsaro decrypt ca.pem.encrypted --stdout > certs/ca.pem

# Read file-enc JSON from stdin and decrypt to stdout
cat ca.pem.encrypted | kapsaro decrypt --stdin --stdout > certs/ca.pem
```

> [!WARNING]
> Never commit decrypted plaintext files to Git. Ensure `.gitignore` excludes all plaintext outputs.

### Inspecting Artifact Metadata

You can inspect encrypted file headers and metadata without decrypting payloads:

```bash
kapsaro inspect .kapsaro/secrets/default.kvenc
kapsaro inspect ca.pem.encrypted
```

Displayed information includes:

- Recipient list (`member_handle` and `kid`)
- Signer handle and key identifier
- Cryptographic algorithms
- Created and modified timestamps
- Historical disclosure records

Check the Signature Verification field for `OK`, or `signature_verification.verified` for `true` in JSON output. The command's exit status alone does not establish signature validity. To check access, also use `run -- true` for a KV store or `decrypt --stdout > /dev/null` for a file.

### Format Selection Guide

| Scenario | Recommended Format | Reason |
| :--- | :--- | :--- |
| Application environment variables | kv-enc (`set`, `import`) | Minimal Git diffs, granular entry-level tracking |
| Certificates and PEM files | file-enc (`encrypt`) | Native binary and multiline support |
| SSH private keys | file-enc (`encrypt`) | Preserves formatting and line breaks |
| Large files (tens of MB) | External secure storage | Base64 encoding inflates payload by ~33% |
| Very large files (hundreds of MB) | Not recommended in Git | Avoid bloating Git repository history |

---

<a id="11-member-management"></a>

## 6. Member Management

<a id="member-addition-git-workflow"></a>

<a id="membership-completion"></a>

### Shared Completion Procedure for Membership Changes

After reviewing a `join` pull request, use this procedure for member additions, key replacements, removals, and CI onboarding. Check both the member records and every encrypted file the team shares.

1. Fetch reviewed changes.
   Verify your working directory is clean and pull the approved branch:
   ```bash
   git status --short
   git pull --ff-only
   ```

2. Synchronize recipients with `rewrap`.
   By default, `rewrap` processes all files under `secrets/`. Review the incoming member's identity before confirming:
   ```bash
   kapsaro member list
   kapsaro rewrap
   ```
   If you manage encrypted files outside `secrets/`, process them with `--target`:
   ```bash
   kapsaro rewrap --target certs/ca.pem.encrypted
   ```

3. Verify signatures and decryption.
   Confirm that all files have the intended recipients, valid signatures, and readable contents:
   ```bash
   kapsaro member list
   kapsaro inspect .kapsaro/secrets/default.kvenc
   kapsaro member verify --approve
   kapsaro run -- true
   git diff --stat
   git diff -- .kapsaro/members/ .kapsaro/secrets/
   ```
   For standalone encrypted files:
   ```bash
   kapsaro inspect certs/ca.pem.encrypted
   kapsaro decrypt certs/ca.pem.encrypted --stdout > /dev/null
   ```
   In each `inspect` result, check Signature Verification for `OK` (or `signature_verification.verified` for `true` in JSON). Repeat the KV checks with `-n` for every named store. Verify both `active` and `incoming`, including replacement or removed keys.

4. Commit and share the changes.
   Stage member promotions, incoming file deletions, and updated encrypted files together:
   ```bash
   git add -A -- .kapsaro/members/ .kapsaro/secrets/
   git diff --cached --name-status
   git commit -m "Apply approved member changes and rewrap secrets"
   git push
   ```
   Include encrypted files outside `secrets/` in the diff review and staging commands as well.

5. Verify access from the consuming member or CI job.
   The member pulls the shared commit and checks access:
   ```bash
   git pull --ff-only
   kapsaro member verify --approve
   kapsaro run -- true
   ```
   Check every store and standalone file the consumer needs. For a replacement key, use the [isolated new-key test](#new-key-verification); for CI, verify the shared commit on the runner.

<a id="rewrap-recovery"></a>

### Recovering from a Partial rewrap Failure

If a `rewrap` operation is interrupted or partially fails:

1. Inspect `git status` and `git diff` to identify processed versus failed files.
2. Resolve underlying issues (permissions, lock contentions, or merge conflicts).
3. Re-run `rewrap` specifically targeting the failed files:
   ```bash
   kapsaro rewrap --target .kapsaro/secrets/staging.kvenc
   ```
4. Verify all targets and complete the shared completion procedure.

### Adding Public Key Files Directly

```bash
# Add a public key file to incoming
kapsaro member add bob.public.json

# Commit and push for team review
git add .kapsaro/members/incoming/bob@example.com.json
git commit -m "Add bob to kapsaro (incoming)"
git push
```

### Listing and Verifying Members

```bash
# List all members (active + incoming)
kapsaro member list

# Show detailed information for a member
kapsaro member show bob@example.com

# Verify active members against GitHub and approve
kapsaro member verify --approve
```

### Managing the Local Trust Store

```bash
# List approved keys
kapsaro trust keys list

# Remove a specific key approval
kapsaro trust keys remove <kid>

# List reviewed artifact recipient sets
kapsaro trust recipients list

# Purge approvals older than 180 days
kapsaro trust keys purge --older-than 180d --force
kapsaro trust recipients purge --older-than 180d --force

# Re-sign the trust store with your current active key
kapsaro trust resign
```

### Removing Members

```bash
# Pull latest changes
git status --short
git pull --ff-only

# Remove the member and rewrap secrets
kapsaro member remove alice@example.com
kapsaro rewrap
```

Follow the [shared completion procedure](#membership-completion) to commit and share the removal.

### Post-Removal Credential Rotation

Removing a member and rewrapping every affected file excludes that member from the new recipient set and rotates the content keys. Old ciphertext and previously disclosed values remain usable. Replace the underlying credentials as follows:

1. Identify credentials the departed member could access.
2. Revoke and reissue tokens, passwords, and certificates at their issuing providers.
3. Update Kapsaro with the new values via `--stdin`:
   ```bash
   kapsaro set API_KEY --stdin
   kapsaro set DATABASE_PASSWORD --stdin
   ```
4. After every affected value is replaced and consumers verify the shared updates, optionally clear disclosure metadata:
   ```bash
   kapsaro rewrap --clear-disclosure-history
   ```

Clearing disclosure metadata records your operational decision; it does not revoke credentials or erase Git history.

---

<a id="12-key-management-and-rotation"></a>

## 7. Key Management and Rotation

### Core Principles

- Commit public keys under `.kapsaro/members/` and keep private keys in your protected local keystore.
- Protect the Ed25519 SSH key that protects your Kapsaro private key, including with a strong passphrase.
- Respond to suspected compromise from a trusted workstation. Replace the affected SSH key as well as the Kapsaro key, revoke the old SSH key where registered, and remove compromised key approvals with `kapsaro trust keys remove <kid>` on affected workstations.

The regular workflow below replaces the member key. If that key may have leaked, also ensure the compromised key is absent from both `active` and `incoming`, run `rewrap --rotate-key` on every affected file, and revoke exposed credentials at their issuing services. A replacement key under the same handle can retain the existing content master key unless you request rotation. Do not retain compromised keys for the routine transition period.

### Key States

| State | Description |
| :--- | :--- |
| active | Local key selected for new operations and signing, one per handle |
| available | Older valid key that can decrypt files addressed to it |
| expired | Past its expiration date; emergency recovery requires an explicit override |

### Regular Key Rotation Workflow

Keys expire one year after generation by default, with warnings displayed 30 days prior.

```bash
# Generate a new local key (becomes active locally)
kapsaro key new

# Submit the new public key to incoming
kapsaro join

# Commit and push for review
git add .kapsaro/members/incoming/alice@example.com.json
git commit -m "Rotate alice's key"
git push
```

Once merged, follow the [shared completion procedure](#membership-completion) to rewrap secrets and push the completion commit.

<a id="new-key-verification"></a>

### Verifying Decryption with Only the New Key

To verify that the new key functions independently of retained older keys, run an isolated test in a temporary directory:

```bash
(
  set -eu
  umask 077
  unset KAPSARO_PRIVATE_KEY KAPSARO_KEY_PASSWORD
  source_home="$HOME/.config/kapsaro"
  new_kid='<new_kid_without_hyphens>'
  rotation_check=$(mktemp -d)
  trap 'rm -rf "$rotation_check"' EXIT
  rotation_home="$rotation_check/home"
  mkdir -p "$rotation_home/keys/alice@example.com"
  cp -R "$source_home/keys/alice@example.com/$new_kid" \
    "$rotation_home/keys/alice@example.com/"
  kapsaro key activate "$new_kid" --home "$rotation_home" \
    --member-handle alice@example.com
  kapsaro key list --home "$rotation_home" --member-handle alice@example.com
  git clone <repo-url> "$rotation_check/repo"
  kapsaro member verify --approve --home "$rotation_home" \
    --workspace "$rotation_check/repo/.kapsaro" --member-handle alice@example.com
  kapsaro run --home "$rotation_home" --workspace "$rotation_check/repo/.kapsaro" \
    --member-handle alice@example.com -- true
)
```

For routine rotation, retain old keys for 1–3 months after verification so teammates have time to pull the updates, then remove them. Compromised keys require the incident response described above:

```bash
kapsaro key remove <old_kid>
```

### Rotating Content Encryption Keys

The content master key (MK) derives the keys used to encrypt a file or KV entries (CEKs). To generate a new MK and re-encrypt the contents of files under `secrets/`:

```bash
kapsaro rewrap --rotate-key
```

Use `--target` for encrypted files elsewhere and complete the [shared verification and commit procedure](#membership-completion). Recipient removal also rotates the MK automatically. Rotation preserves the plaintext values, so it does not replace passwords or tokens at their issuing services.

---

<a id="ci-setup"></a>

<a id="13-cicd-integration"></a>

## 8. CI/CD Integration

CI jobs can load a password-protected private key from environment variables. The runner needs the workspace checkout, but no SSH agent or pre-existing local keystore.

### Operational Model

Environment-key mode supports `run`, `get`, `decrypt`, `list`, and the read-only diagnostic command `doctor`. Perform key generation, rewrapping, and member management on developer workstations. The exported key itself still has cryptographic signing capabilities; these are CLI command restrictions.

For trusted jobs without persistent approvals, set `KAPSARO_STRICT_KEY_CHECKING=no`. This skips the local key approval cache on reads. Signatures, key-possession proofs during decryption, public key validation, active-member authorization, and recipient consistency still apply. Existing unsafe local state or invalid trust stores still cause errors.

Inject CI secrets only when all three conditions hold: maintainers control the workflow, the checkout uses a protected branch/tag or trusted post-merge commit, and the runner is trusted and isolated from untrusted workloads. Do not inject them into fork or untrusted PR jobs, `pull_request_target`, jobs that check out attacker-controlled code, or untrusted runners. After injection, keep the checkout on a trusted revision.

### Setup Workflow

#### Step 1: Create a Dedicated CI Member

```bash
git status --short
git pull --ff-only
kapsaro key new --member-handle ci@example.com
kapsaro join --member-handle ci@example.com
```

#### Step 2: Add the CI Member and Rewrap

```bash
git add .kapsaro/members/incoming/ci@example.com.json
git commit -m "Add CI member"
git push

# After PR is merged:
git pull --ff-only
kapsaro rewrap
git add -A -- .kapsaro/members/ .kapsaro/secrets/
git commit -m "Rewrap secrets for CI member"
git push
```

Use the [shared completion procedure](#membership-completion) to inspect recipients and signatures, test decryption, and include any encrypted files outside `secrets/` in the shared commit.

#### Step 3: Export the Protected CI Private Key

```bash
kapsaro key export --private --member-handle ci@example.com --out ci-key.txt
```

Enter a strong passphrase (at least 20 UTF-8 bytes).

#### Step 4: Configure CI Platform Secrets

Register two secret variables in your CI platform settings:

- `KAPSARO_PRIVATE_KEY`: Content of `ci-key.txt`
- `KAPSARO_KEY_PASSWORD`: The passphrase entered during export

Remove `ci-key.txt` from your workstation after registration and keep it out of Git, logs, and backups. Storing the export and password in the same CI secret backend is supported, but compromise of that backend exposes both; password protection mainly protects an exported file leaked on its own.

On the runner, confirm `kapsaro run -- true` succeeds against the shared commit before running the deployment. Check all required named stores and files. For CI key replacement, update both variables, verify with the new key, remove the old recipient key, and share the rewrapped files.

### GitHub Actions Example

This example pins Kapsaro to `v0.99.2-beta` and verifies the downloaded archive's GitHub attestation before extracting or executing it. Configure `main` and the runner to meet the conditions above.

```yaml
name: Deploy
on:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4

      - name: Install kapsaro
        shell: bash
        run: |
          set -euo pipefail
          command -v curl
          command -v tar
          command -v gh

          kapsaro_tag=v0.99.2-beta
          kapsaro_archive="kapsaro-${kapsaro_tag}-x86_64-unknown-linux-gnu.tar.gz"
          kapsaro_bundle="kapsaro-${kapsaro_tag}.sigstore.jsonl"
          kapsaro_url="https://github.com/ebisawa/kapsaro/releases/download/${kapsaro_tag}"
          kapsaro_download="$(mktemp -d "${RUNNER_TEMP}/kapsaro-download.XXXXXX")"
          kapsaro_install="$(mktemp -d "${RUNNER_TEMP}/kapsaro-bin.XXXXXX")"
          trap 'rm -rf "${kapsaro_download}"' EXIT

          curl -fsSL "${kapsaro_url}/${kapsaro_archive}" \
            -o "${kapsaro_download}/${kapsaro_archive}"
          curl -fsSL "${kapsaro_url}/${kapsaro_bundle}" \
            -o "${kapsaro_download}/${kapsaro_bundle}"
          gh attestation verify "${kapsaro_download}/${kapsaro_archive}" \
            --bundle "${kapsaro_download}/${kapsaro_bundle}" \
            --repo ebisawa/kapsaro \
            --signer-workflow ebisawa/kapsaro/.github/workflows/release.yml

          tar -xzf "${kapsaro_download}/${kapsaro_archive}" -C "${kapsaro_install}"
          kapsaro_version="$("${kapsaro_install}/kapsaro" --version)"
          printf '%s\n' "${kapsaro_version}"
          if [[ "${kapsaro_version}" != "kapsaro ${kapsaro_tag#v}" ]]; then
            echo "::error::Unexpected kapsaro version"
            exit 1
          fi
          printf '%s\n' "${kapsaro_install}" >> "${GITHUB_PATH}"

      - name: Run with secrets
        env:
          KAPSARO_PRIVATE_KEY: ${{ secrets.KAPSARO_PRIVATE_KEY }}
          KAPSARO_KEY_PASSWORD: ${{ secrets.KAPSARO_KEY_PASSWORD }}
          KAPSARO_STRICT_KEY_CHECKING: "no"
        shell: bash
        run: |
          set -euo pipefail
          kapsaro run -- true
          kapsaro run -- ./deploy.sh
```

---

<a id="10-workspace-health-checks"></a>

## 9. Diagnostics

`kapsaro doctor` inspects workspace structure, local keys, trust records, and permissions without modifying them.

```bash
kapsaro doctor
kapsaro doctor --verbose
kapsaro doctor --workspace .kapsaro --home ~/.config/kapsaro
```

Run it when reviewing a join request, before and after `rewrap` or key rotation, and when configuring `KAPSARO_PRIVATE_KEY` for CI. It also helps with release checks, periodic audits, workstation migration, and local state recovery.

The checks cover:

- Workspace structure and Git association
- Active and incoming member records, key expiration, duplicate `kid` values, and GitHub verification
- Local keystore readiness and active private key access
- Local trust store approvals
- Permissions and ownership under `<KAPSARO_HOME>`
- Temporary files left by interrupted writes
- Integrity and signatures of encrypted files under `.kapsaro/secrets/`
- The environment key when `KAPSARO_PRIVATE_KEY` is configured

### Diagnostic Status Meanings

| Status | Meaning | Action |
| :--- | :--- | :--- |
| OK | The check passed | No action needed for this check |
| WARN | Review, approval, or key rotation may be needed | Review the finding and its recommended action |
| FAIL | A problem requires resolution | Follow the displayed `Next` action before continuing |
| SKIP | A prerequisite was missing | Supply it, such as network access, and rerun |

For a completed diagnostic report, `doctor` returns status `1` if it contains a FAIL finding. A successful check covers only what that check examined.

### Local State Permissions

Restrict `<KAPSARO_HOME>` to its owner: directories use `0700` and files use `0600`.

```bash
chmod -R go-rwx ~/.config/kapsaro
kapsaro doctor
```

---

<a id="14-faq"></a>

## 10. Troubleshooting and FAQ

### General Questions

#### Q: Is a Dedicated Server or SaaS Required?
No dedicated service is required. Encryption, decryption, and signature verification run locally. Optional GitHub identity verification requires network access.

#### Q: Do I Need GPG or PGP?
No. Local key protection uses an Ed25519 SSH key; Kapsaro manages its own encryption and signing keys.

#### Q: Do I Need a Team Master Password?
No. Kapsaro uses HPKE to protect a shared content master key separately for each recipient's public key.

#### Q: Is It Safe to Commit `.kapsaro/members/` to GitHub?
These files contain public keys and identity metadata, not private keys. They can be committed for team sharing, but check the member identities and other visible metadata before publishing the repository.

#### Q: Why Is the SSH Agent Needed?

An SSH agent provides signatures without giving Kapsaro the SSH private key file. Those signatures protect or unlock the local Kapsaro key. If you prefer direct signing, use `--ssh-keygen --ssh-identity ~/.ssh/id_ed25519`, or set `ssh_signing_method = "ssh-keygen"` in global configuration. See the [WSL guide](wsl_user_guide_en.md) for Windows-hosted SSH agents.

<a id="git-conflict-resolution"></a>

### Resolving Git Conflicts in Encrypted Files

#### Q: What Should I Do If Encrypted Files Conflict During a Git Merge?

A KV store encrypts values per key, but the digital signature covers the entire document. When concurrent branches modify different keys, shared lines (such as the signature) will conflict. Never resolve conflicts by manually stitching encrypted lines together. Instead, preserve both sides' commits and replay changes onto a known-good document.

Assuming a `git merge` stopped with conflicts:

1. Preserve both commits in temporary branches.
   ```bash
   git status --short
   git branch recovery/local HEAD
   git branch recovery/other MERGE_HEAD
   ```

2. Agree on the intended changes.
   Review with authors which keys were added, updated, or removed.

3. Restore the starting document from a known-good commit.
   ```bash
   base_commit=$(git rev-parse recovery/other)
   git restore --source="$base_commit" --worktree -- .kapsaro/secrets/default.kvenc
   kapsaro inspect .kapsaro/secrets/default.kvenc
   ```
   Confirm that Signature Verification reports `OK`. If membership differed, rewrap first:
   ```bash
   kapsaro rewrap --target .kapsaro/secrets/default.kvenc
   ```

4. Replay missing changes with `set` and `unset`.
   ```bash
   kapsaro set DATABASE_URL --stdin
   kapsaro set API_TOKEN --stdin
   kapsaro unset OLD_KEY
   ```

5. Verify and complete the merge.
   ```bash
   kapsaro inspect .kapsaro/secrets/default.kvenc
   kapsaro list
   kapsaro run -- true
   git add -A -- .kapsaro/members/ .kapsaro/secrets/
   git commit -m "Merge approved secret changes"
   git push
   ```

---

<a id="15-command-reference"></a>

## 11. Command and Configuration Reference

### Common Options

| Option | Description |
| :--- | :--- |
| `--home <path>` | Specify local Kapsaro state directory (default: `~/.config/kapsaro/`) |
| `-w` / `--workspace <path>` | Specify workspace root directory |
| `-m` / `--member-handle <handle>` | Specify active member handle |
| `-i` / `--ssh-identity <path>` | Path to an Ed25519 SSH private key, or its public key for agent signing |
| `--ssh-agent` | Force signing via `ssh-agent` |
| `--ssh-keygen` | Force signing via `ssh-keygen` binary |
| `--json` | Emit structured JSON output |
| `-q` / `--quiet` | Suppress non-essential output |
| `-v` / `--verbose` | Enable verbose operational details |
| `--debug` | Enable internal trace logging |
| `-n` / `--name <name>` | Select named KV store (default: `default`) |
| `-f` / `--force` | Bypass safety confirmations where supported |
| `--allow-expired-key` | Allow emergency recovery decryption with expired keys |

### Commands by Category

| Category | Command | Description |
| :--- | :--- | :--- |
| Setup | `kapsaro init` | Initialize a new workspace and register first member |
| | `kapsaro join` | Submit a request to join an existing workspace |
| KV Store | `kapsaro set <KEY> <VALUE>` | Add or update a secret entry |
| | `kapsaro set <KEY> --stdin` | Read a secret value from standard input |
| | `kapsaro get <KEY>` | Decrypt and print a specific secret |
| | `kapsaro get --all` | Decrypt and print all secrets in the store |
| | `kapsaro unset <KEY>` | Remove a key from the store |
| | `kapsaro list` | List secret names without decrypting values |
| | `kapsaro import <file>` | Bulk-import an existing `.env` file |
| | `kapsaro run -- <cmd>` | Inject secrets as environment variables and execute command |
| File Operations | `kapsaro encrypt <file>` | Encrypt an arbitrary file (file-enc format) |
| | `kapsaro decrypt <file>` | Decrypt a file-enc artifact |
| | `kapsaro inspect <file>` | Inspect artifact metadata, signatures, and recipients |
| Diagnostics | `kapsaro doctor` | Run health checks on workspace, keys, and trust state |
| Members | `kapsaro member list` | List all workspace members and their key IDs |
| | `kapsaro member show <handle>` | Display detailed member metadata |
| | `kapsaro member verify --approve` | Verify member keys against GitHub and approve |
| | `kapsaro member add <file>` | Add a public key file to `members/incoming/` |
| | `kapsaro member remove <handle>` | Remove a member from the workspace |
| | `kapsaro rewrap` | Synchronize recipients and promote incoming keys |
| Trust Store | `kapsaro trust keys list` | List approved keys in local trust store |
| | `kapsaro trust keys remove <kid>` | Remove a key approval record |
| | `kapsaro trust recipients list` | List reviewed artifact recipient sets |
| | `kapsaro trust resign` | Re-sign local trust store with current active key |
| Key Lifecycle | `kapsaro key new` | Generate a new local keypair |
| | `kapsaro key list` | List local keys and their status |
| | `kapsaro key activate <kid>` | Switch active local signing key |
| | `kapsaro key remove <kid>` | Remove a local keypair |
| | `kapsaro key export` | Export public key document |
| | `kapsaro key export --private` | Export password-protected private key for CI/CD |
| Configuration | `kapsaro config set <k> <v>` | Set a global configuration value |
| | `kapsaro config get <k>` | Read a global configuration value |
| | `kapsaro config list` | List all global configuration values |

---

<a id="16-configuration-reference"></a>

### Configuration Priority

Kapsaro resolves configuration values in the following order:

1. CLI options (highest priority)
2. Environment variables
3. Config file (`~/.config/kapsaro/config.toml`)
4. Built-in defaults (lowest priority)

### Configuration Keys (`config.toml`)

```toml
member_handle = "alice@example.com"
workspace = "~/src/project/.kapsaro"
ssh_identity = "~/.ssh/id_ed25519"
ssh_signing_method = "auto"
github_user = "alice-gh"
allow_expired_key = "no"
allow_non_member = "no"
```

### Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `KAPSARO_HOME` | State directory for configuration, keystore, and trust store | `~/.config/kapsaro/` |
| `KAPSARO_MEMBER_HANDLE` | Default member handle | (none) |
| `KAPSARO_SSH_IDENTITY` | Path to an Ed25519 SSH private key, or its public key for agent signing | `~/.ssh/id_ed25519` |
| `KAPSARO_SSH_SIGNING_METHOD` | Signing method: `auto`, `ssh-agent`, `ssh-keygen` | `auto` |
| `KAPSARO_GITHUB_USER` | Default GitHub login to associate with a newly generated public key | (none) |
| `KAPSARO_WORKSPACE` | Explicit workspace root path | (auto-detected) |
| `KAPSARO_STRICT_KEY_CHECKING` | Enforce local trust store checks on read (`yes`, `no`) | `yes` |
| `KAPSARO_ALLOW_EXPIRED_KEY` | Allow emergency recovery with expired keys (`yes`, `no`) | `no` |
| `KAPSARO_ALLOW_NON_MEMBER` | Allow one-shot confirmation for non-member signers on supported reads; `run` always rejects them | `no` |
| `KAPSARO_PRIVATE_KEY` | Portable private key for headless CI environments | (none) |
| `KAPSARO_KEY_PASSWORD` | Passphrase for `KAPSARO_PRIVATE_KEY` in CI | (none) |

---

<a id="3-common-terms"></a>

## 12. Glossary

### Workspace

The directory containing member public keys and encrypted files, usually `.kapsaro/`. Inside Git, Kapsaro detects the workspace at the repository root. Outside Git, it detects `.kapsaro/` directly under the current directory. Use `-w` / `--workspace` to select another location.

### `active` and `incoming`

In the workspace, `incoming` holds keys awaiting review; `active` holds approved recipients' public keys. The local keystore also uses the word `active` for the key currently selected for a member.

### `rewrap`

The operation that synchronizes encrypted files' recipients after membership or key changes and promotes approved `incoming` keys to `active`. Removing recipients or passing `--rotate-key` also generates a new content master key and re-encrypts the contents.

### Member Handle

A member's chosen identifier, such as `alice@example.com`. An email-like handle need not be a working address and is not a verified external identity.

### `kid` (Key Identifier)

An identifier derived from a public key. It distinguishes key generations when a member retains multiple keys during rotation.

### Local Trust Store

Signed local records under `~/.config/kapsaro/trust/`. `known_keys` records approved key identities; `recipient_sets` records reviewed recipient sets. Commands such as `member verify --approve` save approvals to avoid repeated review. Current workspace authorization comes from `members/active/`.
