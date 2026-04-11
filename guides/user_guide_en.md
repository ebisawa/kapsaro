# secretenv User Guide

> A self-contained guide for teams getting started with secretenv.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Design Philosophy](#2-design-philosophy)
3. [Core Concepts](#3-core-concepts)
4. [Security Model](#4-security-model)
5. [Installation](#5-installation)
6. [Quick Start (Team Leader)](#6-quick-start-team-leader)
7. [Joining as a New Member](#7-joining-as-a-new-member)
8. [Daily Usage (KV Store)](#8-daily-usage-kv-store)
9. [File Encryption and Decryption](#9-file-encryption-and-decryption)
10. [Member Management](#10-member-management)
11. [Key Management and Rotation](#11-key-management-and-rotation)
12. [CI/CD Integration](#12-cicd-integration)
13. [Operational Guidelines](#13-operational-guidelines)
14. [FAQ](#14-faq)
15. [Command Reference](#15-command-reference)
16. [Configuration Reference](#16-configuration-reference)

---

## 1. Introduction

### What is secretenv?

Team development requires sharing secrets — database passwords, API keys, certificates — among multiple members. Common approaches are often problematic:

- Pasting passwords in plaintext to Slack or Teams
- Leaving real values as comments in `.env.example`
- Former members retaining passwords that were shared with them

secretenv is a CLI tool that solves these problems by **managing encrypted secrets in a Git repository**, allowing teams to share secrets safely and traceably.

### What it solves

- Encrypt `.env` files and certificates and store them in the repository for safe team sharing
- Update access to encrypted files as members are added or removed
- Encrypted files themselves record who had access and when
- Works offline — no server or network required

### What it does not solve

secretenv intentionally omits certain features. These are listed explicitly to prevent overreliance.

- **Insider misuse**: It cannot prevent a legitimate member from misusing decrypted content
- **Revoking past disclosures**: Removing a member does not invalidate values they previously obtained (see [Chapter 10](#10-member-management))
- **Large-scale ACL management**: There is no central policy engine defining who should have access to which secret
- **Key leakage protection**: If local key files are compromised, defense relies on OS-level security

---

## 2. Design Philosophy

### Offline-First

All core operations in secretenv — encryption, decryption, signature verification, rewrap — work without a network connection. Online verification via the GitHub API is an optional feature, not a requirement.

This design ensures consistent operation during network outages or in air-gapped environments.

### Git Integration Model

secretenv manages the `.secretenv/` directory via Git. This has important implications.

**PR review becomes a security gate**: When a new member joins, their public key file is submitted as a PR. Existing members review and merge it just like a code review — no separate approval system is needed.

**Change history is automatic**: `git log` tracks who added or removed members and when secrets were updated.

**Do not add `.secretenv/` to `.gitignore`**. This directory is intentionally managed by Git.

### Policy-Less Design

secretenv has no policy file defining "who can access which secret." Instead, **the encrypted file itself remembers who the recipients are**.

Each encrypted file contains a content key (wrap) encrypted for each recipient. Only the member holding the corresponding private key can decrypt their wrap, extract the content key, and read the secret.

### Diff-Friendly kv-enc

The `kv-enc` format for managing `.env`-style secrets **encrypts each entry individually**.

When only one key's value is updated, only that entry changes — others remain untouched. This minimizes Git diffs and makes review easier. Adding a new entry also does not require decrypting existing entries.

### Disclosure Tracking

When a member is removed and `rewrap` is run, the disclosure history (`removed_recipients`) is recorded in the encrypted file.

This tracks the fact that "a removed member previously had access to this secret." Use `secretenv inspect` to review this history and decide whether to update secret values.

---

## 3. Core Concepts

This chapter defines terms that appear frequently throughout the guide. Reading this before the command chapters will make everything easier to understand.

### Workspace

The `.secretenv/` directory inside a Git repository is the Workspace. It stores encrypted files and member information shared by the team.

```
.secretenv/
├── members/
│   ├── active/       ← public keys of approved members
│   └── incoming/     ← public keys of pending members
├── secrets/          ← encrypted secrets
└── config.toml       ← local configuration (optional)
```

secretenv automatically searches for `.secretenv/` from the current directory upward, stopping at the Git repository root. This means workspace auto-detection **only works when the current directory is inside a Git repository**. To use secretenv outside a Git repository, specify the workspace explicitly with the `-w` / `--workspace` option or the `SECRETENV_WORKSPACE` environment variable.

The command examples in this guide assume that **the current directory is inside the target Git repository** unless otherwise noted.

### Member ID

`member_id` is an ASCII identifier. It must start with an alphanumeric character (`A-Za-z0-9`), may contain only `A-Za-z0-9._@+-`, and its length is 1 to 254 characters (pattern: `^[A-Za-z0-9][A-Za-z0-9._@+-]{0,253}$`). It resembles an email address, but `@` is not required. No actual email is sent or received; it simply serves as a unique identifier within the team.

### kid (Key Statement ID)

`kid` identifies a self-signed key statement. The canonical stored form is a 32-character Crockford Base32 string without hyphens, for example `7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD`.

CLI output, logs, and review screens usually show a dashed display form such as `7M2Q-9D4R-1H8V-W6PK-T3XN-C5JY-2F9A-R8GD`. Input is case-insensitive and hyphen-agnostic, so both forms refer to the same key statement.

A single member can have multiple kids. Encrypted files record which kid was used, local keystore paths and JSON documents use the canonical no-dash form, and human-facing output uses the dashed display form.

### kv-enc (KV Encrypted Format)

An encrypted version of `KEY=VALUE` pairs equivalent to a `.env` file. File extension: `.kvenc`.

Because each entry is encrypted independently, updating one key does not affect others, and Git diffs are minimal. kv-enc is recommended for day-to-day secrets management.

### file-enc (File Encrypted Format)

A format that encrypts an entire file (text or binary). File extension: `.encrypted`. Suitable for sharing certificates and binary files.

### active / incoming

Represents a member's approval state.

- **incoming**: A member who has just submitted a join request via `secretenv join`. Not yet included as a recipient in encrypted files.
- **active**: A member approved by an existing member via `rewrap`. Included as a recipient in encrypted files.

### rewrap

The operation that updates recipient information in all encrypted files after members are added or removed.

- Promotes incoming members to active
- Synchronizes the active member list with recipients in all encrypted files
- For kv-enc, regenerates the content key (MK) and re-encrypts all entries when a member is removed

### Local Trust Store and TOFU Approval Cache

The local trust store (`~/.config/secretenv/trust/`) is a TOFU approval cache that stores previously approved `kid`s as `known_keys`.

- `kid`s approved during `member verify --approve` or interactive `rewrap` review are recorded there
- Later read-path and write-path operations use `known_keys` to avoid asking again for the same `kid`
- If the trust store is corrupted, forged, or the corresponding local keystore public key is missing, SecretEnv warns and asks whether to delete it and continue with an empty cache

See [Chapter 10](#10-member-management) for the operational workflow.

---

## 4. Security Model

### Trust Model (4 Layers)

secretenv decides whether to accept a signed artifact through four layers. Trust is established through a combination of layers, not a single mechanism.

| Layer | Mechanism | What it checks | Limitation |
|-------|-----------|---------------|------------|
| Layer 1: Cryptographic verification | Self-signature + SSH attestation | Key authenticity, consistency, and binding | Does not prove identity |
| Layer 2: Authorization | `members/active` directory | Whether the signer/recipient is a current member | Depends on repository governance (PR review) |
| Layer 3: Approval cache | `known_keys` in local trust store | Whether this `kid` was previously approved | Does not imply current membership |
| Layer 4: Manual approval + online verify | `member verify` / interactive `rewrap`, GitHub API | Supplementary evidence for identity decisions | Invalid if GitHub account is compromised |

- **Layer 1** verifies the embedded `signer_pub` in each signed artifact: self-signature (key consistency), SSH attestation (key binding), `kid` match, and expiration. This happens automatically without consulting the workspace.
- **Layer 2** checks that the signer's `(member_id, kid)` exists in `members/active`. This is the authorization source for current membership, but depends on PR review, not cryptography.
- **Layer 3** checks the local trust store (`~/.config/secretenv/trust/`) for previously approved `kid`s. The trust-store file itself is verified with the owner's local keystore public key selected by `signature.kid`. If verification fails, SecretEnv warns, asks whether to delete the corrupted cache, and can continue with an empty cache only after explicit confirmation. Use `secretenv member verify --approve` to populate it. Use `secretenv trust list` / `trust remove` / `trust purge` to manage it.
- **Layer 4** provides human review: during `rewrap` promotion or `member verify`, the operator sees the GitHub account, SSH fingerprint, and `kid` to make a TOFU approval decision.

For the full security analysis, see the [Security Design](security_design_en.md) document (§2.5).

### Threat Model

| Attacker | Capability | Defense |
|----------|-----------|---------|
| Repository tamperer | Can modify files in `.secretenv/` | Tampering detected by signature verification |
| Malicious insider | Retains decrypted content as a legitimate member | Tracked via disclosure history (recovery impossible) |
| Public key substitution attack | Forges a member's public key file | Defended by self-signature, attestation, and online verification |
| Key rotation attack | Attempts to reuse wraps bound to older key statements | kid is included in HPKE info, so statement mismatch is detected |
| First-contact MITM | Replaces bootstrap-time kid or attestation fingerprint with attacker-controlled values | TOFU-based manual review and out-of-band verification |
| Local trust store tamperer | Can write to or roll back `~/.config/secretenv/trust/` | Trust-store signature for corruption detection, OS/filesystem access control |

**Assumptions**: This defense model assumes that write access to the repository is properly managed. On GitHub, changes to `members/active/` are verified through PR review. `members/active` is the authorization source for the current member set, but it is not a cryptographic trust anchor. The local trust store (`~/.config/secretenv/trust/`) is assumed to be protected by OS-level access control. Bootstrap-time and first-seen `kid` trust decisions rely on TOFU.

### Trust Boundary

```
[Trusted (secure)]
  Local machine
  ~/.config/secretenv/keys/   ← local keystore
  ~/.config/secretenv/trust/  ← local trust store (TOFU approval cache)
  SSH Ed25519 private key

[Workspace (potentially tampered)]
  .secretenv/members/active/    ← authorization source for current member set
  .secretenv/members/incoming/  ← pending join requests
  .secretenv/secrets/           ← defended by signature verification

[External systems (optional)]
  GitHub API                    ← used only for online verification
```

### Role of the SSH Key

In secretenv, the SSH key is not the key that directly decrypts workspace secrets. It has two roles:

1. Protect the secretenv private key stored locally under `~/.config/secretenv/keys/`
2. Through attestation, show which SSH key backs that secretenv key

The key that actually decrypts and signs file-enc / kv-enc data is the secretenv private key after it has been unlocked locally. Think of the SSH key as the outer key that makes the local secretenv private key usable.

---

## 5. Installation

### Prerequisites

- Ed25519 SSH key (`~/.ssh/id_ed25519`)
- SSH agent (recommended) or ssh-keygen

### Install via Homebrew (Recommended)

```bash
brew tap ebisawa/secretenv
brew install secretenv
```

### Install from Source (Alternative)

If you prefer to build from source, a Rust toolchain (`cargo`) is required.

```bash
git clone <secretenv-repo>
cd secretenv
cargo install --path .
```

After installation, run `secretenv --help` to see the list of commands.

### Verify SSH Agent

secretenv uses SSH keys to protect private keys. Verify that your SSH agent is running.

```bash
# Check SSH agent
ssh-add -l

# If no keys are listed, add your key
ssh-add ~/.ssh/id_ed25519
```

**Note**: SSH keys must be in Ed25519 format (RSA and others are not supported).

```bash
# Generate an Ed25519 key if you don't have one
ssh-keygen -t ed25519 -C "your@email.com"
```

### Configuration (Optional)

You can save frequently used options to a configuration file.

```bash
# Set default member_id (allows omitting --member-id going forward)
secretenv config set member_id alice@example.com

# Set GitHub account (for online verification)
secretenv config set github_user alice-gh

# Set SSH signing method (default "auto" works for most cases)
# auto: tries ssh-agent first, then ssh-keygen
# ssh-agent: use SSH agent
# ssh-keygen: use ssh-keygen command
secretenv config set ssh_signing_method auto

# Set SSH key (select a specific key when multiple keys are loaded in ssh-agent)
secretenv config set ssh_identity ~/.ssh/id_ed25519_work
```

The configuration file is located at `~/.config/secretenv/config.toml`.

---

## 6. Quick Start (Team Leader)

Follow these steps when introducing secretenv to your team for the first time.

### Step 1: Prepare a repository

Workspace auto-detection works inside a Git repository. Start by navigating to your Git repository directory.

```bash
# Start with an existing repository
cd /path/to/your-repo

# Or create a new repository
git init my-project
cd my-project
```

### Step 2: Initialize the Workspace

```bash
secretenv init --member-id alice@example.com
```

Output:

```
Creating workspace .secretenv/
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

`init` automatically:

- Creates the `.secretenv/` directory structure
- Generates an HPKE key pair locally (`~/.config/secretenv/keys/alice@example.com/<canonical-kid>/`)
- Registers your public key at `members/active/alice@example.com.json`

### Step 3: Add your first secrets

```bash
# Add secrets in KV format
secretenv set DATABASE_URL "postgres://user:pass@localhost/mydb"
secretenv set API_KEY "sk-your-api-key"

# Or bulk-import an existing .env file
secretenv import .env
```

### Step 4: Commit to Git

```bash
git add .secretenv/
git commit -m "Initialize secretenv workspace"
```

### Step 5: Have team members join

Once the Workspace is ready, direct other members to the steps in [Chapter 7](#7-joining-as-a-new-member).

When a member submits a PR, approve it following the [member addition workflow in Chapter 10](#member-addition-git-workflow).

---

## 7. Joining as a New Member

Follow these steps to join an existing Workspace.

### Step 1: Clone the repository

Clone the repository and navigate into the directory. This allows secretenv to auto-detect the workspace.

```bash
git clone <repo-url>
cd my-project
```

### Step 2: Submit a join request

```bash
secretenv join --member-id bob@example.com
```

Output:

```
Using SSH key: SHA256:xxxxx... (from ~/.ssh/id_ed25519)
Generated and activated key for 'bob@example.com':
  Key ID:   9N4R-1H8V-W6PK-T3XN-C5JY-2F9A-R8GD-7M2Q
  Expires:  2027-03-19T00:00:00Z
Added 'bob@example.com' to members/incoming/

Ready! Create a PR to share your public key with the team.
An existing member needs to run 'secretenv rewrap' to approve your membership.
```

Unlike `init`, `join` does not create a Workspace — it only places your public key in `members/incoming/`.

### Step 3: Create a PR

```bash
git checkout -b join/bob
git add .secretenv/members/incoming/bob@example.com.json
git commit -m "Add bob to secretenv (incoming)"
git push origin join/bob
```

Create a PR on GitHub (or your Git hosting service) and request a review from existing members.

### Step 4: Ask an existing member to run rewrap

After the PR is merged, an existing member runs `secretenv rewrap` to approve you. Once rewrap is committed, you will be able to access secrets.

### Step 5: Verify access and trust existing members

```bash
# Pull the latest changes
git pull

# Verify access
secretenv get DATABASE_URL
secretenv run -- env | grep MY_APP

# Register existing members' keys in your local trust store
secretenv member verify --approve
```

The last command registers the team's existing keys in your local trust store, preventing approval prompts during future operations.

---

## 8. Daily Usage (KV Store)

### Adding and Updating Entries

```bash
# Basic usage
secretenv set DATABASE_URL "postgres://user:pass@localhost/db"

# Save to a different store (with -n option)
secretenv set -n staging DATABASE_URL "postgres://user:pass@staging/db"
secretenv set -n prod DATABASE_URL "postgres://user:pass@prod/db"
```

If no store is specified, the value is saved to `default` (`.secretenv/secrets/default.kvenc`).

**To avoid leaving secrets in shell history**: use `--stdin` for passwords and tokens.

```bash
# Pipe the value
echo "super-secret-token" | secretenv set SECRET_TOKEN --stdin

# Interactive input (for passwords)
secretenv set SECRET_TOKEN --stdin
# → Waits for input. Press Ctrl+D to confirm.
```

### Removing Entries

```bash
secretenv unset OLD_KEY
secretenv unset -n staging OLD_KEY
```

### Retrieving Entries

```bash
# Get a specific key's value
secretenv get DATABASE_URL

# Output in KEY="VALUE" format
secretenv get --with-key DATABASE_URL

# Get all entries
secretenv get --all

# Get all entries in KEY="VALUE" format
secretenv get --all --with-key

# Get from a different store
secretenv get -n staging DATABASE_URL
```

### Listing Keys

```bash
# List key names (values are not displayed)
secretenv list

# List keys from a different store
secretenv list -n staging
```

`list` shows only key names without decrypting anything. Use `get` to retrieve values.

### Running Commands with Secrets Injected as Environment Variables

```bash
# Inject all secrets from the default store as environment variables
secretenv run -- ./my-app

# Use a different store
secretenv run -n staging -- ./my-app

# Pass multiple arguments
secretenv run -- python manage.py runserver
```

`run` does not inherit the parent process environment wholesale. The child process keeps only standard variables such as `PATH` and `HOME`, then overlays secret values on top.

### Bulk Importing a .env File

```bash
# Import .env into the default store
secretenv import .env

# Import into a different store
secretenv import -n staging staging.env
```

Existing keys are overwritten.

---

## 9. File Encryption and Decryption

Use `encrypt` / `decrypt` for secrets that don't fit the KV format, such as certificates and binary files.

### Encrypting

```bash
# Encrypt a file (generates <filename>.encrypted in the current directory)
secretenv encrypt certs/ca.pem
# → ./ca.pem.encrypted

# Specify an output path
secretenv encrypt certs/ca.pem --out .secretenv/secrets/ca.pem.encrypted
```

A signature is attached automatically during encryption.

### Decrypting

```bash
# Signature verification is performed before decryption
secretenv decrypt ca.pem.encrypted --out certs/ca.pem
```

### Inspecting Metadata

You can examine an encrypted file's metadata without decrypting it.

```bash
secretenv inspect .secretenv/secrets/default.kvenc
secretenv inspect ca.pem.encrypted
```

Information displayed:

- List of recipients
- Signer and signing kid
- Encryption algorithm
- Created and updated timestamps
- Disclosure history (records of access by removed members)

### When to Use Which Format

| Scenario | Recommended | Reason |
|----------|-------------|--------|
| `.env` key-value pairs | kv-enc (`set`, `import`) | Minimal diff, entry-level operations |
| Certificate files (PEM) | file-enc (`encrypt`) | Binary support |
| SSH private keys | file-enc (`encrypt`) | Binary support |
| Files tens of MB or larger | Consider external storage | Base64 encoding inflates size by ~4/3 |
| Files hundreds of MB or larger | Not recommended | Adds large files to the Git repository |

---

## 10. Member Management

### Member Addition Git Workflow

When a new member submits a PR via `secretenv join`, follow this flow to approve them.

**Why PR review matters**: Reviewing and merging a PR is the decision to "trust this person's public key." Merging a PR from an unknown person without review means adding them as a recipient of your secrets.

```bash
# 1. After merging the new member's PR, pull the latest
git pull

# 2. Run rewrap
#    - Automatically runs online verification (GitHub API lookup)
#    - TOFU review (visually verify the displayed key information)
secretenv rewrap

# TOFU review example:
# Member bob@example.com
#   GitHub account id: 12345678 (bob-gh)
#   SSH key fingerprint: SHA256:xxxxx...
# Approve? [y/N]: y    ← verify this is really their key before pressing y

# 3. Commit and push changes
git add .secretenv/
git commit -m "Approve bob and rewrap secrets"
git push
```

After `rewrap` completes:
- `members/incoming/bob@example.com.json` moves to `members/active/`
- Bob's wrap (encrypted content key) is added to all encrypted files

**Recommended**: After rewrap, register the new member's key in your local trust store to avoid approval prompts on future operations:

```bash
secretenv member verify --approve
```

### Listing Members

```bash
# Show all members (active + incoming)
secretenv member list

# Show details for a specific member
secretenv member show bob@example.com
```

### Verifying Members

```bash
# Verify public keys for active members (with online verification)
secretenv member verify

# Verify specific active members only
secretenv member verify alice@example.com bob@example.com

# Verify active members and persist approvals in the local trust store
secretenv member verify --approve

# Restrict approval to specific active members
secretenv member verify --approve alice@example.com bob@example.com
```

`member verify --approve` targets only `members/active`. It performs offline verification and, when needed, online verification, then shows the `kid`, GitHub account `id`, the `login` when available, and the SSH fingerprint for review. Only approved non-self `kid`s are written to `known_keys` in the local trust store. Your own keys that already exist in the local keystore are treated as self-trusted for the approval-cache check and are not normally added to `known_keys`, but this does not bypass the current `members/active` check.

### Managing the Local Trust Store

```bash
# List approved known_keys
secretenv trust list

# Remove one kid from the local trust store
secretenv trust remove <kid>

# Purge old approvals in bulk
secretenv trust purge --older-than 180d --force
```

`trust remove` and `trust purge` change only the local approval cache. They do not modify workspace membership or recipients in encrypted files.

### Removing Members

**Important**: Removing a member and running rewrap **does not invalidate secret values that member previously obtained**. It is cryptographically impossible to "revoke past disclosures."

```bash
# 1. Remove the member from the workspace
secretenv member remove alice@example.com

# 2. Run rewrap (removes alice from all encrypted files)
#    For kv-enc: content key (MK) is regenerated and all entries are re-encrypted
#    For file-enc: alice's wrap is removed
secretenv rewrap

# 3. Commit
git add .secretenv/
git commit -m "Remove alice from secretenv"
```

### Required Steps After Removal

1. **Update secret values**: Change any values the removed member knew to new values.

```bash
secretenv set API_KEY "new-api-key"
secretenv set DATABASE_PASSWORD "new-password"
```

2. **Review disclosure history**: Use `secretenv inspect` to check disclosure records for the removed member.

3. **Clear disclosure history**: After updating secret values, you can clear the disclosure history.

```bash
secretenv rewrap --clear-disclosure-history
```

---

## 11. Key Management and Rotation

### Key States

| State | Description |
|-------|-------------|
| active | Key used for encryption and signing. One per member_id. |
| available | Can decrypt but is not used for encryption or signing. |
| expired | Past expiration date. Can still decrypt (with a warning). |

### Listing Keys

```bash
secretenv key list
```

The CLI displays kids in dashed display form. Local keystore paths and JSON documents use the canonical no-dash form. Commands such as `key activate`, `key remove`, and `key export` accept either form, and `key list` is ordered by `created_at` descending with canonical `kid` as the tiebreaker.

### Regular Rotation

Keys expire one year after generation by default. Warnings appear starting 30 days before expiration.

**Summary**: (1) `key new` → (2) `init --force` → (3) PR and merge → (4) `rewrap` → (5) commit → (6) remove old key after transition period.

```bash
# 1. Generate a new key (automatically becomes active)
secretenv key new

# Specify an expiration date
secretenv key new --expires-at 2028-01-01T00:00:00Z
secretenv key new --valid-for 2y    # 2 years
secretenv key new --valid-for 180d  # 180 days

# 2. Update your public key in the workspace
secretenv init --force

# 3. Create and merge a PR
git add .secretenv/members/active/alice@example.com.json
git commit -m "Rotate alice's key"
git push

# 4. After merge: update wraps in all secrets with the new key
secretenv rewrap

# 5. Commit
git add .secretenv/secrets/
git commit -m "Rewrap secrets for alice's new key"
git push

# 6. Keep the old key for now (may be needed to decrypt past secrets)
#    Remove after a sufficient transition period
secretenv key remove <old_kid>
```

### Content Key Rotation

Separately from member key rotation, you can rotate the content keys (MK/DEK) of encrypted files themselves.

```bash
secretenv rewrap --rotate-key
```

This regenerates the MK/DEK for all files, invalidating any content keys previously obtained by removed members.

### Activating a Specific Key

```bash
secretenv key activate <kid>
```

### Recommended Old Key Retention Period

Before deleting an old key, confirm:

- All team members have obtained encrypted files rewrapped with the new key
- No operations remain that require decrypting secrets encrypted with the old key

As a guideline, retain old keys for 1–3 months after rewrap completion.

---

## 12. CI/CD Integration

secretenv supports CI/CD environments through portable private key export and environment variable-based key loading, **but only in trusted CI contexts**. This eliminates the need for SSH keys, `ssh-agent`, or a local keystore in CI runners.

### Overview

In CI environments, secretenv reads the private key and password from environment variables instead of the local keystore. Environment variable-based key loading guarantees read-only commands: `run`, `decrypt`, `get`, and `list` are supported.

CI runners are typically ephemeral and do not have a local trust store (`~/.config/secretenv/trust/`). This means the approval cache (Layer 3 of the trust model) is unavailable. To allow read operations to succeed, set `SECRETENV_STRICT_KEY_CHECKING=no` for the CI job. This skips only the `known_keys` cache check — the `members/active` authorization check (Layer 2) and cryptographic signature verification (Layer 1) remain enforced.

The workspace checkout remains input to signature verification. Environment variable-based key loading must therefore be limited to **trusted workflow / trusted ref / trusted runner** contexts.

### Allowed CI Contexts

- post-merge workflows on protected branches
- release / deploy workflows on protected tags
- manual dispatch jobs started by trusted maintainers on trusted refs

### Forbidden CI Contexts

- fork PRs
- untrusted PRs
- `pull_request_target`
- jobs that checkout attacker-controlled refs after secrets are injected
- jobs on untrusted runners

### Minimal CI Requirements

Only three things are needed in a trusted CI context:

1. `SECRETENV_PRIVATE_KEY` environment variable — the exported private key (Base64url-encoded)
2. `SECRETENV_KEY_PASSWORD` environment variable — the password used during export
3. A workspace (Git repository containing `.secretenv/` directory)

No `SECRETENV_HOME`, local keystore, SSH key, or config file is required.

If a trusted CI job has no local trust store and must run a read-path command against artifacts signed by other active members, explicitly set `SECRETENV_STRICT_KEY_CHECKING=no` only for that job. This skips only the `known_keys` check. It does not skip the `members/active` check, does not skip cryptographic signature verification, and does not auto-update `known_keys`.

### Setup Workflow

#### Step 1: Create a Dedicated CI Member

Create a dedicated member for CI (do not reuse a human member's key).

```bash
# On a developer machine with SSH key access
secretenv key new --member-id ci@example.com
secretenv init --member-id ci@example.com --force
```

#### Step 2: Add the CI Member to Recipients

```bash
git add .secretenv/members/active/ci@example.com.json
git commit -m "Add CI member"
git push

# After merge: add CI member to all encrypted files
secretenv rewrap
git add .secretenv/secrets/
git commit -m "Rewrap secrets for CI member"
git push
```

#### Step 3: Export the Private Key

```bash
# Run this on a developer machine with SSH signer and local keystore access
secretenv key export --private --member-id ci@example.com --out ci-key.txt
# You will be prompted to enter and confirm a password (minimum 8 characters)
```

> **Password strength:** The 8-character minimum is an implementation-enforced floor, not a recommendation. For offline brute-force resistance, use 20 or more random characters (or a passphrase with equivalent entropy). A CI secret variable generated by a password manager is ideal.

The output file contains a single line of Base64url-encoded text. If you intentionally need stdout output, pass `--stdout` explicitly.

#### Step 4: Register in CI Secret Variables

Register two secret variables in your CI platform:

| Variable | Value |
|----------|-------|
| `SECRETENV_PRIVATE_KEY` | Contents of `ci-key.txt` |
| `SECRETENV_KEY_PASSWORD` | The password you entered during export |

After registering, securely delete the `ci-key.txt` file. Do not relay the private key through CI job logs, stdout, or ad-hoc artifacts.

#### Step 5: Use in CI Jobs

CI jobs can use only the secret-operation commands that already support environment variable-based key loading. The `member_id` is automatically determined from the private key.

### Example: GitHub Actions

```yaml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install secretenv
        run: cargo install --path .

      - name: Run with secrets
        env:
          SECRETENV_PRIVATE_KEY: ${{ secrets.SECRETENV_PRIVATE_KEY }}
          SECRETENV_KEY_PASSWORD: ${{ secrets.SECRETENV_KEY_PASSWORD }}
          SECRETENV_STRICT_KEY_CHECKING: no
        run: secretenv run -- ./deploy.sh
```

This example assumes a **trusted post-merge workflow on a protected branch**. Do not reuse the same pattern for `pull_request` or `pull_request_target` jobs that expose secrets.

### Example: Generic CI Configuration

```bash
# Any CI platform that checks out a trusted ref and supports secret environment variables
export SECRETENV_PRIVATE_KEY="<registered secret>"
export SECRETENV_KEY_PASSWORD="<registered secret>"
export SECRETENV_STRICT_KEY_CHECKING=no

# Only commands supporting environment variable-based key loading work
secretenv get DATABASE_URL
secretenv run -- ./my-app
secretenv decrypt ca.pem.encrypted --out ca.pem
```

### Supported Operations

Environment variable-based key loading guarantees only the secret-operation commands currently implemented for env dispatch:

- **Decryption** (`run`, `decrypt`, `get`): uses the KEM private key from the environment variable
- **Listing** (`list`): shows kv-enc key names as metadata only

All other commands remain unavailable when loading keys via environment variables:

- **Secret mutation / re-signing** (`encrypt`, `set`, `unset`, `import`, `rewrap`)
- **Key lifecycle** (`key new`, `key list`, `key activate`, `key remove`, `key export`, `key export --private`)
- **Setup** (`init`, `join`)
- **Other helper commands** (`inspect`, `member`, `config`, etc.)

### Security Considerations

- **Password exposure**: `SECRETENV_KEY_PASSWORD` persists in process memory and may be visible via `/proc/*/environ` on Linux. This is consistent with how CI platforms handle secrets.
- **Trusted CI only**: Use environment variable-based key loading only in trusted workflow / trusted ref / trusted runner contexts. Attacker-controlled checkouts must not be used as signature-verification input.
- **Scope of `SECRETENV_STRICT_KEY_CHECKING=no`**: This is an explicit read-path exception for jobs that cannot use a local trust store. It has no effect on write commands and does not auto-update `known_keys`.
- **Dedicated CI member**: Always use a dedicated CI member rather than a human member's key. This allows independent rotation and revocation.
- **Key rotation**: Rotate the CI member key and re-export with `key export --private` on a developer machine with SSH signer and local keystore access, then update the CI platform's secret store.
- **Least privilege**: Only add the CI member to the secrets it actually needs access to.

---

## 13. Operational Guidelines

### Checklist When a Member Leaves

1. Remove the member with `secretenv member remove <member_id>`
2. Update all encrypted files with `secretenv rewrap`
3. Commit with `git add .secretenv/ && git commit -m "Remove <member>"`
4. Review disclosure history with `secretenv inspect`
5. Update any secret values (API keys, passwords, etc.) the departing member may have known
6. After updating, clear disclosure history with `secretenv rewrap --clear-disclosure-history`
7. Confirm access revocation in related services (GitHub, AWS, databases, etc.)

### Obligation to Rotate Secret Values

**Cryptographic removal is not information erasure.** `member remove` + `rewrap` prevents the member from decrypting new secrets going forward, but it cannot invalidate values they have already decrypted.

For true security, always rotate any values that departing or removed members may have known.

### Interactive Approval in `rewrap`

When incoming members exist, `rewrap` requires interactive approval: the operator must visually verify each candidate's key information (GitHub account, SSH fingerprint) and confirm with `y`. If no incoming members exist (i.e., only recipient synchronization is needed), `rewrap` runs non-interactively.

Note: Environment variable-based key loading for CI/CD does not support `rewrap`. See [Chapter 12: CI/CD Integration](#12-cicd-integration) for details.

### Regular Auditing with `secretenv inspect`

```bash
# Check metadata for each encrypted file
secretenv inspect .secretenv/secrets/default.kvenc

# Things to verify:
# - No unnecessary members in recipients
# - No notable entries in removed_recipients (disclosure history)
# - Signer is correct
# - No nearly-expired keys are being used
```

### What Not to Add to `.gitignore`

Do not add the entire `.secretenv/` directory to `.gitignore`. It is intentionally managed by Git.

However, decrypted plaintext files should be added to `.gitignore`.

```gitignore
# Ignore decrypted temporary files
*.pem
.env
```

---

## 14. FAQ

### General

### Q: Is a server required?

No. secretenv operates without a server. All core operations — encryption, decryption, signature verification — work entirely locally. Online verification via the GitHub API is an optional additional check.

### Q: Do I need GPG?

No. secretenv works with SSH keys (Ed25519) only. No GPG or PGP key management required.

### Q: Do I need a cloud Secrets Manager?

No. Encryption, decryption, and key management all happen locally. There is no dependency on KMS or cloud services.

### Q: Do I need to manage a shared secret key for the team?

No. secretenv uses public-key cryptography (HPKE), so there is no shared secret key for the entire team. Each member's public key is used for individual encryption, eliminating the burden of distributing, managing, and rotating a common password or shared key.

### Q: Is it safe to commit public key files to GitHub?

Yes. `members/active/*.json` contains public keys (the encryption public key and the SSH public key fingerprint), but no private keys whatsoever. Public keys are, by definition, safe to share publicly.

Decrypting secrets requires the private key stored locally at `~/.config/secretenv/keys/`. This private key is never included in Git.

### Q: Is it safe to make the repository public if secrets are encrypted?

Encrypted files are protected by modern cryptography (HPKE, XChaCha20-Poly1305), making decryption without the private key extremely difficult. However, making a repository public carries operational risks beyond encryption strength (key leakage, future advances in cryptanalysis, etc.). For highly sensitive data, keeping the repository private is recommended.

### SSH Keys

### Q: Do I need to create a new SSH key?

If you already have an Ed25519 key (e.g., for GitHub), you can reuse it. Otherwise, generate one with `ssh-keygen -t ed25519`. RSA and other key types are not supported.

### Q: Why is the SSH agent needed?

secretenv private keys (HPKE private keys) are protected by an SSH Ed25519 key instead of a passphrase. Every secretenv operation requires decryption using the SSH key, so using an SSH agent is convenient to avoid entering a passphrase each time.

In environments where an SSH agent is unavailable, you can switch to signing with the `ssh-keygen` command using the `--ssh-keygen` option.

When multiple keys are loaded in the SSH agent, you can explicitly specify which key to use with the `-i` option or the `ssh_identity` configuration:

```bash
secretenv encrypt -i ~/.ssh/id_ed25519_work secret.env
```

### Q: Does it work with 1Password's SSH agent?

Yes. secretenv supports signing via ssh-agent, including 1Password's SSH agent. See the [WSL User Guide](wsl_user_guide_en.md) for Windows/WSL2-specific configuration.

### Daily Usage

### Q: Can I migrate from an existing .env file?

Yes. `secretenv import .env` imports everything at once. Then use `secretenv run` to execute commands with decrypted secrets injected as environment variables.

### Q: Can I encrypt files other than .env?

Yes. Certificates, configuration files, and arbitrary binaries can be handled with `secretenv encrypt` / `secretenv decrypt`. See [Chapter 9](#9-file-encryption-and-decryption).

### Q: Can I manage multiple environments (dev / staging / prod)?

Yes. Use the `-n` option to create separate stores for each environment:

```bash
secretenv set -n staging DATABASE_URL "postgres://..."
secretenv set -n prod DATABASE_URL "postgres://..."
secretenv run -n staging -- ./my-app
```

### Q: Should I use `secretenv run` or manually load a `.env` file?

`secretenv run` is recommended for these reasons:

- No plaintext `.env` file is left on disk
- The latest secrets are decrypted on each run, so value updates take effect immediately
- Signature verification runs automatically, preventing command execution with tampered secrets
- It reduces accidental leakage of arbitrary parent-shell environment variables into the child process

### Q: How do I manage separate secrets for multiple projects?

Each Git repository can have its own independent `.secretenv/`. Run `secretenv init` in each project to manage them as independent Workspaces.

Even if the same member participates in multiple projects, their HPKE key is registered as an independent recipient in each Workspace.

### Q: What happens if encrypted files conflict in Git?

secretenv encrypts each `.env` key individually, so changes to different keys rarely conflict. If the same key is modified simultaneously, resolve the conflict by choosing one side, just like any other Git conflict.

### Membership and Keys

### Q: Does removing a member erase past secrets?

No. Removing a member and running rewrap does not eliminate values that member has already decrypted — those values may still exist on their machine.

To eliminate the risk of exposure after removal, always rotate the values (API keys, passwords, etc.) the member may have known.

### Q: Is key rotation supported?

Yes. `secretenv rewrap --rotate-key` regenerates encryption keys and re-encrypts everything. This supports both member changes and periodic rotation. See [Chapter 11](#11-key-management-and-rotation).

### Q: Does it work in CI/CD environments?

Yes. `secretenv run` and `secretenv get` work non-interactively via environment variable-based key loading. See [Chapter 12](#12-cicd-integration) for setup details, allowed contexts, and security considerations.

### Troubleshooting

### Q: SSH agent errors — "no keys" or "agent not running"

Run `ssh-add -l` to check. If empty, add your key with `ssh-add ~/.ssh/id_ed25519`. If the agent is not running, start it with `eval "$(ssh-agent -s)"`.

### Q: "Key expired" warnings or errors

Keys expire one year after generation by default. Follow the rotation procedure in [Chapter 11](#11-key-management-and-rotation): generate a new key with `secretenv key new`, update the workspace with `secretenv init --force`, then run `secretenv rewrap`.

### Q: Unexpected approval prompts when decrypting

This occurs when the signer's `kid` is not in your local trust store. Run `secretenv member verify --approve` to review and approve current active members. See [Chapter 10](#10-member-management) for details.

### Q: "Non-deterministic SSH signature" error

This means your SSH key produced different signatures for the same input on two consecutive attempts. This can happen with FIDO2/hardware tokens (Ed25519-SK). secretenv requires deterministic Ed25519 signatures. Use a standard software Ed25519 key instead.

---

## 15. Command Reference

### Common Options (Available for All Commands)

| Option | Description |
|--------|-------------|
| `--home <path>` | Specify base directory (default: `~/.config/secretenv/`) |
| `-w` / `--workspace <path>` | Specify Workspace Root |
| `-i` / `--ssh-identity <path>` | Specify SSH key file path (also used for key selection with ssh-agent) |
| `--ssh-agent` | Use SSH agent |
| `--ssh-keygen` | Use ssh-keygen command |
| `--json` | Output in JSON format |
| `-q` / `--quiet` | Minimal output |
| `-v` / `--verbose` | Verbose logging |

### Initialization and Joining

| Command | Description |
|---------|-------------|
| `secretenv init [--member-id <id>] [--force]` | Initialize a Workspace or re-register yourself (added directly to active) |
| `secretenv join [--member-id <id>] [--force]` | Request to join an existing Workspace (added to incoming) |

### KV Operations

| Command | Description |
|---------|-------------|
| `secretenv set [-n <name>] <KEY> <VALUE>` | Add or update an entry |
| `secretenv set [-n <name>] <KEY> --stdin` | Read value from stdin and set it |
| `secretenv get [-n <name>] <KEY>` | Retrieve and display a specific key's value |
| `secretenv get [-n <name>] --all` | Retrieve and display all entries |
| `secretenv get [-n <name>] [--all] --with-key` | Output in `KEY="VALUE"` format |
| `secretenv unset [-n <name>] <KEY>` | Remove an entry |
| `secretenv list [-n <name>]` | List key names (values not displayed) |
| `secretenv import [-n <name>] <file>` | Bulk import a `.env` file |
| `secretenv run [-n <name>] -- <command>` | Run a command with secrets injected as environment variables |

### File Operations

| Command | Description |
|---------|-------------|
| `secretenv encrypt <file> [--out <path>]` | Encrypt a file (file-enc) |
| `secretenv decrypt <file> --out <path>` | Decrypt a file |
| `secretenv inspect <file>` | Display encrypted file metadata (no decryption needed) |

### Member Management

| Command | Description |
|---------|-------------|
| `secretenv member list` | List all members |
| `secretenv member show <member_id>` | Show details for a specific member |
| `secretenv member verify [<member_id>...]` | Verify active member public keys (with online verification) |
| `secretenv member verify --approve [<member_id>...]` | Verify active members and save approved `kid`s into the local trust store |
| `secretenv member add <file>` | Add a member's public key file to incoming |
| `secretenv member remove <member_id>` | Remove a member from the Workspace |
| `secretenv rewrap [--rotate-key] [--clear-disclosure-history]` | Promote incoming → active and sync recipients in all encrypted files |

### Local Trust Store

| Command | Description |
|---------|-------------|
| `secretenv trust list` | List `known_keys` in the local trust store |
| `secretenv trust remove <kid>` | Remove a specific `kid` from the local trust store |
| `secretenv trust purge --older-than <duration> [-f, --force]` | Remove approvals older than the given duration from the local trust store |

### Key Management

| Command | Description |
|---------|-------------|
| `secretenv key new [--expires-at <datetime>] [--valid-for <duration>]` | Generate a new key (automatically activated) |
| `secretenv key list` | List keys |
| `secretenv key activate <kid>` | Activate a specific key |
| `secretenv key remove <kid>` | Remove a key |
| `secretenv key export [<kid>] [--member-id <id>] --out <path>` | Export public key |
| `secretenv key export --private [<kid>] [--member-id <id>] (--stdout \| --out <path>)` | Export private key (password-protected, for CI/CD) |

### Configuration

| Command | Description |
|---------|-------------|
| `secretenv config set <key> <value>` | Set a configuration value |
| `secretenv config get <key>` | Get a configuration value |
| `secretenv config list` | List all configuration values |
| `secretenv config unset <key>` | Remove a configuration value |

Configuration keys: `member_id`, `ssh_signing_method` (`auto` / `ssh-agent` / `ssh-keygen`), `ssh_identity`, `github_user`

---

## 16. Configuration Reference

secretenv resolves configuration values from multiple sources in the following priority order:

1. **CLI options** (highest priority)
2. **Environment variables**
3. **Config file** (`<SECRETENV_HOME>/config.toml`)
4. **Default values** (lowest priority)

When a higher-priority source provides a value, lower-priority sources are ignored.

### Config File

The global config file is located at `<SECRETENV_HOME>/config.toml` (default: `~/.config/secretenv/config.toml`). It uses flat TOML key-value format.

| Key | Description | Default | CLI Option | Environment Variable |
|-----|-------------|---------|------------|---------------------|
| `member_id` | Default member identifier (pattern: `^[a-z][a-z0-9-]{0,31}$`) | (none) | `-m` / `--member-id` | `SECRETENV_MEMBER_ID` |
| `ssh_identity` | Path to SSH private key file (Ed25519). Supports tilde expansion (`~/...`) | `~/.ssh/id_ed25519` | `-i` / `--ssh-identity` | `SECRETENV_SSH_IDENTITY` |
| `ssh_signing_method` | SSH signing method: `auto`, `ssh-agent`, `ssh-keygen` | `auto` | `--ssh-agent` / `--ssh-keygen` | `SECRETENV_SSH_SIGNING_METHOD` |
| `ssh_keygen_command` | Path to `ssh-keygen` command | `ssh-keygen` | — | — |
| `ssh_add_command` | Path to `ssh-add` command | `ssh-add` | — | — |
| `github_user` | Default GitHub login name for `key new` | (none) | `--github-user` | `SECRETENV_GITHUB_USER` |

Example:

```toml
member_id = "alice"
ssh_identity = "~/.ssh/id_ed25519"
ssh_signing_method = "auto"
github_user = "alice-gh"
```

If the config file does not exist, secretenv falls back to environment variables and default values without error. If the file exists but contains syntax errors, secretenv reports an error.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRETENV_HOME` | Base directory for secretenv configuration and keys | `~/.config/secretenv/` |
| `SECRETENV_MEMBER_ID` | Default member identifier | (none) |
| `SECRETENV_SSH_IDENTITY` | Path to SSH private key file (Ed25519) | `~/.ssh/id_ed25519` |
| `SECRETENV_SSH_SIGNING_METHOD` | SSH signing method: `auto`, `ssh-agent`, `ssh-keygen` | `auto` |
| `SECRETENV_GITHUB_USER` | Default GitHub login name for `key new` | (none) |
| `SECRETENV_WORKSPACE` | Workspace directory path (overrides auto-detection) | (auto-detected from git root) |
| `SECRETENV_STRICT_KEY_CHECKING` | Trust store strict checking for read-path: `yes`, `no` | `yes` |
| `SECRETENV_PRIVATE_KEY` | Base64url-encoded portable private key document (CI/CD) | (none) |
| `SECRETENV_KEY_PASSWORD` | Password for `SECRETENV_PRIVATE_KEY` (CI/CD) | (none) |

**Notes:**

- `SECRETENV_PRIVATE_KEY` and `SECRETENV_KEY_PASSWORD` are used together for CI/CD environments where a local keystore is not available. When `SECRETENV_PRIVATE_KEY` is set, `SECRETENV_KEY_PASSWORD` is required. See [Chapter 12](#12-cicd-integration) for details.
- `SECRETENV_STRICT_KEY_CHECKING=no` disables the `known_keys` check on the read path. This is permitted only for read operations (decrypt, get, run, list). Write-path operations always enforce strict checking.
- `SECRETENV_WORKSPACE` overrides the automatic workspace detection from the git repository root. Useful when running commands outside the repository tree.

---

*This guide covers everything needed for day-to-day secretenv usage. For detailed cryptographic specifications and internal design, refer to the project's internal documentation.*
