# kapsaro User Guide

## Table of Contents

1. [Introduction](#1-introduction)
2. [What to Know Before You Start](#2-what-to-know-before-you-start)
3. [Common Terms](#3-common-terms)
4. [Security Basics for Users](#4-security-basics-for-users)
5. [Installation](#5-installation)
6. [Quick Start (Team Leader)](#6-quick-start-team-leader)
7. [Joining as a New Member](#7-joining-as-a-new-member)
8. [Daily Usage (KV Store)](#8-daily-usage-kv-store)
9. [File Encryption and Decryption](#9-file-encryption-and-decryption)
10. [Workspace Health Checks](#10-workspace-health-checks)
11. [Member Management](#11-member-management)
12. [Key Management and Rotation](#12-key-management-and-rotation)
13. [CI/CD Integration](#13-cicd-integration)
14. [FAQ](#14-faq)
15. [Command Reference](#15-command-reference)
16. [Configuration Reference](#16-configuration-reference)

---

## 1. Introduction

### What is kapsaro?

Team development requires sharing secrets — database passwords, API keys, certificates — among multiple members. Common approaches are often problematic:

- Pasting passwords in plaintext to Slack or Teams
- Leaving real values as comments in `.env.example`
- Former members retaining passwords that were shared with them

kapsaro is a CLI tool that solves these problems by **managing encrypted secrets in a Git repository**, allowing teams to share secrets safely and traceably.

### What it solves

- Encrypt `.env` files and certificates and store them in the repository for safe team sharing
- Update access to encrypted files as members are added or removed
- Encrypted files themselves record who had access and when
- Works offline — no server or network required

### What it does not solve

kapsaro is not a complete solution to every security problem. It does not automatically solve what happens after decryption, how to revoke values that were already seen, or how to protect compromised machines and keys. See [Chapter 4](#4-security-basics-for-users) for these assumptions and limits.

---

## 2. What to Know Before You Start

### Start with the big picture

It helps to think about kapsaro in this order:

1. The team shares encrypted secrets and member information in a workspace inside the Git repository
2. Each user has their own public key and private key
3. New members and rotated keys are reviewed, then approved as secret recipients

The next sections explain the tool in that order.

### Share the workspace through Git

The workspace is the `.kapsaro/` directory in your Git repository. This is where the team shares secrets and member information.

```
.kapsaro/
├── members/
│   ├── active/
│   └── incoming/
├── secrets/
└── config.toml
```

- `members/active/`: public keys for current members
- `members/incoming/`: public keys waiting for approval or rotation
- `secrets/`: encrypted secrets

`.kapsaro/` is part of normal operation, so do not add it to `.gitignore`.

### Understand the role of the keys first

Each user has their own key pair.

- A **public key** can be shared with the team
- A **private key** must stay with that user

The basic idea of public-key encryption is simple: **encrypt with a public key, decrypt with the matching private key**. In kapsaro, secrets are encrypted for recipients' public keys, so only users with the matching private keys can decrypt them. In other words, it does not depend on securely distributing one team-wide shared secret key.

With shared-key encryption, everyone who needs access must somehow receive the same secret key securely, so **how to distribute that shared secret** becomes an operational problem in itself. With public-key encryption, you only distribute public keys, so you do not need to distribute the secret material that must remain private.

The important rule is that **a private key must never be shared with anyone else**. Giving someone your private key is effectively giving them the ability to read secrets as you. Do not commit it to Git, paste it into chat, or share it carelessly through backups or exports.

By contrast, **a public key is something you should actively share even though it is called a "key."** A public key alone normally cannot decrypt the secret. That is why it is safe to commit public-key files under `members/active/` or `members/incoming/`.

The difficult part is **knowing whose public key it really is**. A public key can be safe to share and still be falsely presented as "Alice's key" by an attacker. In practice, the hard problem is not distributing public keys, but deciding **which person a given public key should be trusted to represent**.

### How a member becomes usable

New members and rotated keys first go into `members/incoming/`. They become usable recipients only after an existing member reviews the PR and runs `kapsaro rewrap`.

In practice, **PR review is part of member approval**. During review, you are not only checking that "a public key was added" but also deciding whether that key should be trusted as belonging to that person. Do not merge unfamiliar public keys casually.

### Two formats you will use most

- **kv-enc**: For `.env`-style key-value secrets. This is the recommended default for day-to-day use.
- **file-enc**: For encrypting an entire file such as a certificate or binary.

For operations, see [Chapter 8](#8-daily-usage-kv-store) and [Chapter 9](#9-file-encryption-and-decryption).

---

## 3. Common Terms

### Workspace

The workspace is the `.kapsaro/` directory. When you run kapsaro inside a Git repository, it usually finds the workspace automatically. In a layout without `.git`, it also auto-detects `.kapsaro/` directly under the current directory. If the workspace is elsewhere, specify it explicitly with `-w` / `--workspace`.

### `active` / `incoming`

- **incoming**: A public key that is not approved yet
- **active**: An approved public key that can be a recipient of secrets

### `rewrap`

The operation that updates recipient information after a member change or key rotation. It is also what turns an `incoming` key into an active one.

### `member handle`

A self-asserted handle that a user keeps using across Kapsaro workspaces. It often looks like an email address, but it does not have to be a real email address or a verified external identifier.

### `kid`

An ID that identifies a key. A single member can have multiple keys, so `kid` tells you which one is being used. You will mostly see it in `key list` and `rewrap` output.

### Local trust store

The local record of approved keys under `~/.config/kapsaro/trust/`. Commands such as `member verify --approve` store approvals there so you are not asked the same question repeatedly.

---

## 4. Security Basics for Users

### What kapsaro protects

Secrets stored in Git are encrypted, and signatures are verified. Even if the repository is shared, the content cannot be read without the right private key.

### What kapsaro does not automatically protect

- What legitimate members do after they decrypt a secret
- Copies or memories of values that were already seen
- Leakage of the local machine or private keys themselves

Removing a member does not erase secrets they already saw. If needed, rotate the secret values themselves.

### What remains visible as plaintext metadata

What kapsaro protects cryptographically is the secret value or the file content in file-enc. Some metadata remains visible in plaintext because it is needed for operation and audit.

- kv-enc key names
- Recipient lists (`member_handle` / `kid`)
- The signer's `kid`
- Created and updated timestamps
- Disclosure history

This is why `list` can show key names without decryption and `inspect` can show recipients, timestamps, and disclosure history without decryption. If you need to conceal environment-variable names, recipient relationships, timestamps, or disclosure history themselves, you need additional operational controls. Depending on the case, use repository access control or split workspaces.

### Role of the SSH key

The SSH Ed25519 key is not the key that directly decrypts workspace secrets. It is used to protect the local kapsaro private key and to show which SSH key is backing that kapsaro key.

In workflows that use GitHub-backed online verify, the tool also checks whether `attestation.pub` is still present in that GitHub account's **current** SSH public-key list. Removing an SSH public key from GitHub therefore stops future online verification that depends on that key. This does not erase existing attestation, but it is a practical way to stop future approvals or trust updates that rely on that key.

### Practical rules when in doubt

- Do not merge unfamiliar public keys in PRs
- Do not share private keys or SSH keys with others
- If leakage or loss is suspected, rotate with `key new` → `join` → `rewrap`
- If you use GitHub-backed verification, remove old SSH public keys from GitHub after the migration is complete

If you need the deeper design background, see [Security Design](security_design_en.md).

---

## 5. Installation

### Prerequisites

- Ed25519 SSH key (`~/.ssh/id_ed25519`)
- SSH agent (recommended) or ssh-keygen

### Install via Homebrew (Recommended)

```bash
brew tap ebisawa/kapsaro
brew install kapsaro
```

### Install from Source (Alternative)

If you prefer to build from source, a Rust toolchain (`cargo`) is required.

```bash
git clone <kapsaro-repo>
cd kapsaro
cargo install --path .
```

After installation, run `kapsaro --help` to see the list of commands.

### Verify SSH Agent

kapsaro uses SSH keys to protect private keys. Verify that your SSH agent is running.

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

---

## 6. Quick Start (Team Leader)

Follow these steps when introducing kapsaro to your team for the first time.

### Step 1: Prepare a repository

Workspace auto-detection works inside a Git repository. In a layout without `.git`, it auto-detects only `.kapsaro/` directly under the current directory. Start by navigating to the directory that contains the workspace.

```bash
# Start with an existing repository
cd /path/to/your-repo

# Or create a new repository
git init my-project
cd my-project
```

### Step 2: Initialize the Workspace

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

`init` automatically:

- Creates the `.kapsaro/` directory structure
- Generates your local key pair in the keystore
- Registers your public key at `members/active/alice@example.com.json`

If the workspace already exists with active members, `init` exits without changes. Use `join` to submit a key to an existing workspace.

### Step 3: Add your first secrets

```bash
# Add secrets in KV format
kapsaro set DATABASE_URL "postgres://user:pass@localhost/mydb"
kapsaro set API_KEY "sk-your-api-key"

# Or bulk-import an existing .env file
kapsaro import .env
```

### Step 4: Verify the added secrets

```bash
kapsaro list
kapsaro get DATABASE_URL
kapsaro run -- env | grep DATABASE_URL
```

At this point, confirm that the key name is listed, the value can be read, and the value can be injected into a child process as an environment variable. See [Chapter 8](#8-daily-usage-kv-store) for the full `list`, `get`, and `run` usage.

### Step 5: Commit to Git

```bash
git add .kapsaro/
git commit -m "Initialize kapsaro workspace"
```

### Step 6: Have team members join

Once the Workspace is ready, direct other members to the steps in [Chapter 7](#7-joining-as-a-new-member).

When a member submits a PR, approve it following the [member addition workflow in Chapter 11](#member-addition-git-workflow).

---

## 7. Joining as a New Member

Follow these steps to join an existing Workspace.

### Step 1: Clone the repository

Clone the repository and navigate into the directory. This allows kapsaro to auto-detect the workspace.

```bash
git clone <repo-url>
cd my-project
```

### Step 2: Submit a join request

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

Unlike `init`, `join` does not create a Workspace — it only places your public key in `members/incoming/`. Existing active members can also use `join` after `key new` to stage a rotated key generation in `members/incoming/`.

### Step 3: Create a PR

```bash
git checkout -b join/bob
git add .kapsaro/members/incoming/bob@example.com.json
git commit -m "Add bob to kapsaro (incoming)"
git push origin join/bob
```

Create a PR on GitHub (or your Git hosting service) and request a review from existing members.

### Step 4: Ask an existing member to run rewrap

After the PR is merged, an existing member runs `kapsaro rewrap` to approve you. Once rewrap is committed, you will be able to access secrets.

### Step 5: Verify access and trust existing members

```bash
# Pull the latest changes
git pull

# Verify access
kapsaro get DATABASE_URL
kapsaro run -- env | grep MY_APP

# Register existing members' keys in your local trust store
kapsaro member verify --approve
```

The last command registers the team's existing keys in your local trust store, preventing approval prompts during future operations.

---

## 8. Daily Usage (KV Store)

### Adding and Updating Entries

```bash
# Basic usage
kapsaro set DATABASE_URL "postgres://user:pass@localhost/db"

# Save to a different store (with -n option)
kapsaro set -n staging DATABASE_URL "postgres://user:pass@staging/db"
kapsaro set -n prod DATABASE_URL "postgres://user:pass@prod/db"
```

If no store is specified, the value is saved to `default` (`.kapsaro/secrets/default.kvenc`).

To avoid leaving passwords or tokens in shell history, do not write the value as a command-line argument. Use `--stdin` and enter the value through stdin instead.

```bash
# Interactive input (for passwords)
kapsaro set SECRET_TOKEN --stdin
# → Waits for input. Press Ctrl+D to confirm.
```

### Removing Entries

```bash
kapsaro unset OLD_KEY
kapsaro unset -n staging OLD_KEY
```

### Retrieving Entries

```bash
# Get a specific key's value
kapsaro get DATABASE_URL

# Output in KEY="VALUE" format
kapsaro get --with-key DATABASE_URL

# Get all entries
kapsaro get --all

# Get all entries in KEY="VALUE" format
kapsaro get --all --with-key

# Get from a different store
kapsaro get -n staging DATABASE_URL
```

### Listing Keys

```bash
# List key names (values are not displayed)
kapsaro list

# List keys from a different store
kapsaro list -n staging
```

`list` does not decrypt values. It verifies the encrypted file's signature, trust decision, and key-possession proof before showing key names. Use `get` to retrieve values.

### Running Commands with Secrets Injected as Environment Variables

```bash
# Inject all secrets from the default store as environment variables
kapsaro run -- ./my-app

# Use a different store
kapsaro run -n staging -- ./my-app

# Pass multiple arguments
kapsaro run -- python manage.py runserver
```

`run` inherits the parent process environment. However, parent environment variables whose names start with `KAPSARO_` are not passed to the child process. Decrypted secret values are applied last, so they override any parent environment variable with the same name.

### Bulk Importing a .env File

```bash
# Import .env into the default store
kapsaro import .env

# Import into a different store
kapsaro import -n staging staging.env
```

Existing keys are overwritten.

---

## 9. File Encryption and Decryption

Use `encrypt` / `decrypt` for secrets that don't fit the KV format, such as certificates and binary files.

### Encrypting

```bash
# Encrypt a file (generates <filename>.encrypted in the current directory)
kapsaro encrypt certs/ca.pem
# → ./ca.pem.encrypted

# Specify an output path
kapsaro encrypt certs/ca.pem --out .kapsaro/secrets/ca.pem.encrypted

# Encrypt from stdin and save to a file
cat certs/ca.pem | kapsaro encrypt --stdin --out .kapsaro/secrets/ca.pem.encrypted

# Encrypt from stdin and emit file-enc JSON to stdout
cat certs/ca.pem | kapsaro encrypt --stdin --stdout > ca.pem.encrypted
```

A signature is attached automatically during encryption.

Batch `rewrap` automatically covers files under `.kapsaro/secrets/` only when `--target` is not provided. If you want to rewrap only a specific file-enc artifact, use `kapsaro rewrap --target <path>` so only the specified file is processed.

### Decrypting

```bash
# Signature verification is performed before decryption
kapsaro decrypt ca.pem.encrypted --out certs/ca.pem

# Write decrypted output to stdout
kapsaro decrypt ca.pem.encrypted --stdout > certs/ca.pem

# Read file-enc JSON from stdin and decrypt it
cat ca.pem.encrypted | kapsaro decrypt --stdin --stdout > certs/ca.pem
```

Do not manage decrypted plaintext files in Git. `.kapsaro/` belongs in Git, but decrypted `.env` files, certificates, and other plaintext outputs should be covered by `.gitignore`.

### Inspecting Metadata

You can examine an encrypted file's metadata without decrypting it.

```bash
kapsaro inspect .kapsaro/secrets/default.kvenc
kapsaro inspect ca.pem.encrypted
```

Information displayed:

- List of recipients
- Signer and signing kid
- Encryption algorithm
- Created and updated timestamps
- Disclosure history (records of access by removed members)

`inspect` is also useful for periodic audits. Check that there are no unnecessary recipients, no disclosure-history entries you need to review, the signer is what you expect, and no nearly expired keys are still in use.

### When to Use Which Format

| Scenario | Recommended | Reason |
|----------|-------------|--------|
| `.env` key-value pairs | kv-enc (`set`, `import`) | Minimal diff, entry-level operations |
| Certificate files (PEM) | file-enc (`encrypt`) | Binary support |
| SSH private keys | file-enc (`encrypt`) | Binary support |
| Files tens of MB or larger | Consider external storage | Base64 encoding inflates size by ~4/3 |
| Files hundreds of MB or larger | Not recommended | Adds large files to the Git repository |

---

## 10. Workspace Health Checks

`kapsaro doctor` is a read-only command for checking whether the current workspace and local state are ready to use safely. Start with the default output for the overall status, then use `--verbose` when you need lower-level reasons.

```bash
kapsaro doctor
kapsaro doctor --verbose
kapsaro doctor --workspace .kapsaro --home ~/.config/kapsaro
```

Run it before or after work such as:

- Reviewing a new member join request
- Running `rewrap` or completing key rotation
- Configuring `KAPSARO_PRIVATE_KEY` for CI/CD
- Release preparation or periodic workspace audits
- Investigating trust, recipient, signature, key-expiry, or GitHub verification warnings
- Moving to another workstation, importing keys, or recovering local state

`doctor` checks:

- Workspace structure and Git binding
- Active and incoming member files, key expiry, duplicate `kid` values, and GitHub binding or verification state
- Local keystore availability and active private key readiness
- Local trust store approvals for active members
- Encrypted artifacts under `.kapsaro/secrets/`
- CI environment-key readiness when `KAPSARO_PRIVATE_KEY` is set

Artifact checks verify metadata, signatures, recipients, and disclosure history while secret payloads remain encrypted.

Read the result from top to bottom.

1. Summary
   Check `Status`, the target workspace, the OK / WARN / FAIL / SKIP counts, and the number of checked artifacts. Use this section first to understand the overall state.
2. Next actions
   Shows the next work to perform when action is needed. When multiple findings recommend the same action, this section deduplicates it.
3. Findings
   Shows details for WARN, FAIL, and SKIP checks. `Target` is the affected item, `Reason` explains why it was reported, and `Next` shows the recommended follow-up.
4. Healthy areas
   Summarizes categories that did not report problems. You do not need to read every individual OK check.
5. Details
   Shows supplemental information such as the target workspace and check count. With `--verbose`, it also includes check ids and lower-level reasons.

Interpret `Status` as follows.

| Status | How to read it |
|--------|----------------|
| OK | Ready to use without follow-up action |
| WARN | Operation can usually continue, but review, approval, rotation, or configuration confirmation is needed |
| FAIL | Do not continue using the workspace as-is. Follow `Next` in `Findings`, then run `doctor` again |
| SKIP | The check could not run because of missing setup, offline conditions, or unmet prerequisites. If the skipped check matters, satisfy the prerequisite and run it again |

The command exits with status 1 only when a FAIL finding exists. WARN and SKIP findings exit with status 0 so local troubleshooting flows can continue while you review the details. In CI, use `--json` and inspect `status`, `next_actions`, and `checks` if the workflow needs its own policy for allowing WARN or SKIP results.

`kapsaro doctor` does not prompt for approval. If it recommends trusting a key, approving a recipient set, or running `rewrap`, run the command shown in the next-action line after reviewing the finding.

---

## 11. Member Management

### Member Addition Git Workflow

When a new member submits a PR via `kapsaro join`, follow this flow to approve them.

**Why PR review matters**: Reviewing and merging a PR is the decision to "trust this person's public key." Merging a PR from an unknown person without review means adding them as a recipient of your secrets.

```bash
# 1. After merging the new member's PR, pull the latest
git pull

# 2. Run rewrap and review the displayed key information
kapsaro rewrap

# Example:
# Member bob@example.com
#   GitHub account: bob-gh (id: 12345678, verified)
#   SSH key fingerprint: SHA256:xxxxx...
# Approve? [y/N]: y    ← verify this is really their key before pressing y

# 3. Commit and push changes
git add .kapsaro/
git commit -m "Approve bob and rewrap secrets"
git push
```

After `rewrap` completes:
- `members/incoming/bob@example.com.json` moves to `members/active/`
- Bob is added as a recipient in all encrypted files

**Recommended**: After rewrap, register the new member's key in your local trust store to avoid approval prompts on future operations:

```bash
kapsaro member verify --approve
```

When incoming members exist, `rewrap` asks for interactive approval. Review the displayed key information and approve it only after deciding that the public key really belongs to that person. If there are no incoming members, `rewrap` usually runs non-interactively because it only needs to synchronize recipient data.

Also note that `rewrap` is not supported when CI/CD uses environment variable-based key loading. Run `rewrap` on a developer machine.

### Adding a Public Key File Directly

Use `member add` when an administrator needs to add a public key file that was received outside the normal `join` PR flow. Before using the file, confirm whose key it is and which GitHub account or SSH fingerprint it is supposed to represent.

```bash
# Add the public key file to incoming
kapsaro member add bob.public.json

# Send the added incoming member file for review
git add .kapsaro/members/incoming/bob@example.com.json
git commit -m "Add bob to kapsaro (incoming)"
git push
```

`member add` only places the public key under `members/incoming/`. The new member still cannot read secrets at that point. After PR review, an existing member runs `rewrap` to promote the incoming key to active and add it as a recipient in encrypted files. Use `member verify --approve` afterward the same way you would for the normal member addition flow.

### Listing Members

```bash
# Show all members (active + incoming)
kapsaro member list

# Show details for a specific member
kapsaro member show bob@example.com
```

The default `member list` output shows each member handle and `kid`. Use this when checking multiple key generations or confirming the state before and after `rewrap`.

### Verifying Members

```bash
# Verify public keys for active members (with online verification)
kapsaro member verify

# Verify specific active members only
kapsaro member verify alice@example.com bob@example.com

# Verify active members and persist approvals in the local trust store
kapsaro member verify --approve

# Restrict approval to specific active members
kapsaro member verify --approve alice@example.com bob@example.com
```

`member verify --approve` is the command you use to review the keys of current active members and save the result on your machine. The command shows identifying information for each key so you can decide whether "this public key really belongs to this person" before approving it. Approved keys are stored in your local trust store, so later operations no longer need to ask for the same confirmation again.

### Managing the Local Trust Store

The local trust store is where your machine remembers which public keys and write-path artifact member sets you have already reviewed. Approved keys prevent repeated key-owner prompts during later operations. Reviewed member sets prevent repeated output sharing prompts before write commands save encrypted artifacts.

`trust keys list` shows the approved keys currently saved on your machine. `trust recipients list` shows reviewed artifact member sets. The local trust store basically grows over time as approvals accumulate, so these commands are useful when you want to clean up entries that are no longer relevant, remove keys that are no longer used, or force yourself to review a key or member set again.

In normal use, approvals are usually recorded automatically through `member verify --approve` or interactive approval flows, so you do not need to manage the trust store manually every day. Use these commands when you want to undo an approval, clean up old approvals, or force yourself to review a key or artifact member set again from scratch.

```bash
# List approved keys
kapsaro trust keys list

# Remove one kid from the local trust store
kapsaro trust keys remove <kid>

# List reviewed artifact member sets
kapsaro trust recipients list

# Remove one reviewed artifact member set
kapsaro trust recipients remove <sid>

# Purge old key approvals in bulk
kapsaro trust keys purge --older-than 180d --force

# Purge old member set reviews in bulk
kapsaro trust recipients purge --older-than 180d --force
```

`trust keys ...` and `trust recipients ...` change only the records on your own machine. They do not modify workspace membership or recipients in encrypted files. In other words, these commands do not change who is in the team; they change how much you will be asked to re-confirm on later operations.

### Removing Members

Use this when you no longer want a member to read future versions of your secrets: for example when someone leaves the team, changes role, loses a device, or should otherwise lose access. Think of it as a two-step process. First, `member remove` takes the member out of the workspace member list. Then `rewrap` updates the encrypted files themselves. After that, the removed member can no longer decrypt the **updated** secrets.

**Important**: Removing a member and running rewrap **does not invalidate secret values that member previously obtained**. It is cryptographically impossible to "revoke past disclosures."

```bash
# 1. Remove the member from the workspace member list
kapsaro member remove alice@example.com

# 2. Update recipient information in encrypted files
kapsaro rewrap

# 3. Commit the change
git add .kapsaro/
git commit -m "Remove alice from kapsaro"
```

Before removal, `member remove` previews encrypted files that still include the member as a recipient and warns that `rewrap` is required. If broken artifacts or signature-invalid artifacts are found during the preview, they are shown as warnings and excluded from the list; the removal itself can still proceed. In non-interactive environments, removal requires `--force`.

At this point, what has changed is **future access**. The secret values themselves have not changed yet, so you still need the follow-up work below.

### Required Steps After Removal

Removing the member and running `rewrap` is not enough by itself. Any values the removed member may already know should be changed if they still matter.

```bash
kapsaro set API_KEY "new-api-key"
kapsaro set DATABASE_PASSWORD "new-password"
```

Then use `kapsaro inspect` to see which files still show disclosure history for that member. This helps you decide which secrets need rotation.

After you finish updating the values, you can clear the disclosure history if needed.

```bash
kapsaro rewrap --clear-disclosure-history
```

In practice, member removal is not complete until you have handled the **secret values that person may already know**, not just the membership records. At the same time, review access in the real services outside kapsaro as well, such as GitHub, AWS, databases, and SaaS tools.

---

## 12. Key Management and Rotation

This chapter is about keeping your own keys usable and safe over time. You will mostly come here when a key is nearing expiration, when compromise is suspected, or when you want to clean up old keys.

### Key Management Principles

At minimum, follow these rules:

- **Public keys may be shared, private keys must not**: only public keys belong in PRs. Private keys stay in your local `~/.config/kapsaro/keys/` and must not be committed to Git or sent through chat
- **You are also responsible for the SSH key that protects the private key**: the kapsaro private key is protected by your SSH Ed25519 key, so careless copying or use on unsafe machines is a real risk
- **Device security is part of key management**: screen lock, disk encryption, account protection, and backup hygiene all matter because they protect the keys indirectly
- **Rotate immediately if compromise or loss is suspected**: if your private key, SSH key, or machine may be unsafe, run `key new` → `join` → `rewrap` and rotate secret values when needed

### Key States

| State | Description |
|-------|-------------|
| active | Key used for encryption and signing. One per member handle. |
| available | Can decrypt but is not used for encryption or signing. |
| expired | Past expiration date. Cannot be used for encryption or signing, and requires explicit recovery allowance for decryption or operational artifact signature verification. |

In everyday use, only the `active` key is used for new encryption and signing. `available` or `expired` keys may still remain because older secrets may still need them for decryption.

Do not use expired keys in normal operation. Rotate before expiration whenever possible. If you must recover older secrets, pass `--allow-expired-key` to the target command, or temporarily set `KAPSARO_ALLOW_EXPIRED_KEY=yes` or `allow_expired_key="yes"`. This allowance only applies to decryption and operational artifact signature verification. It does not allow encryption, signing, or approval of expired PublicKeys with `member verify --approve`.

### Listing Keys

```bash
kapsaro key list
```

Use `key list` when you want to check which key is currently active, whether old keys are still present, or whether an expiration date is approaching. It is a good first step before rotation or cleanup.

The CLI may show kids with hyphens, but commands such as `key activate`, `key remove`, and `key export` accept both hyphenated and non-hyphenated input.

### Key Backup and Workstation Migration

Your local kapsaro private keys are stored under `<KAPSARO_HOME>/keys/`. By default, that is `~/.config/kapsaro/keys/`. When moving to a new workstation, restore this `keys/` directory from a protected backup to the same location on the new machine.

The new machine must also be able to use the same SSH Ed25519 key that protected the kapsaro private key on the old machine. If you use multiple SSH keys, specify the same key with the `-i` option or the `ssh_identity` configuration.

On Unix-like systems, check the restored local directory and file permissions.

```bash
chmod 700 ~/.config/kapsaro ~/.config/kapsaro/keys
find ~/.config/kapsaro/keys -type d -exec chmod 700 {} \;
find ~/.config/kapsaro/keys -type f -exec chmod 600 {} \;
```

First verify that the restored local keys are visible.

```bash
kapsaro key list
```

If you have already checked out an existing workspace, also confirm that you can read and inject a secret.

```bash
kapsaro get DATABASE_URL
kapsaro run -- env | grep DATABASE_URL
```

If a workstation was lost, an SSH key may have leaked, or the backup storage may have been exposed, do not continue operating only from the restored backup. Follow the rotation procedure below to switch to a new key, and rotate actual secret values in their issuing systems when needed.

### Regular Rotation

Rotation is not only for scheduled expiry. You should also rotate when compromise of the private key or the protecting SSH key is suspected. The high-level flow is: create a new key, share the new public key with the team, then update secret recipients to use it.

Keys expire one year after generation by default. Warnings appear starting 30 days before expiration.

**Summary**: (1) `key new` → (2) `join` → (3) PR and merge → (4) `rewrap` → (5) commit → (6) remove old key after transition period.

```bash
# 1. Generate a new local key (it becomes active automatically)
kapsaro key new

# Specify an expiration date
kapsaro key new --expires-at 2028-01-01T00:00:00Z
kapsaro key new --valid-for 2y    # 2 years
kapsaro key new --valid-for 180d  # 180 days

# 2. Submit the new public key to the workspace
kapsaro join

# 3. Create a PR and get it reviewed/merged
git add .kapsaro/members/incoming/alice@example.com.json
git commit -m "Rotate alice's key"
git push

# 4. After merge, switch secret recipient data to the new key
kapsaro rewrap

# 5. Commit that change
git add .kapsaro/secrets/
git commit -m "Rewrap secrets for alice's new key"
git push

# 6. Keep the old key for a while, then remove it later
kapsaro key remove <old_kid>
```

The important point is that `key new` alone changes only your local machine. The workspace does not start using the new key until you share it with `join` and update recipients with `rewrap`.

If your team relies on GitHub online verify, it is useful to **remove the old SSH public key from GitHub after the migration is complete**. Online verify checks whether the key is registered on GitHub now, so deleting the old SSH key makes old attestations backed by that SSH key less likely to pass future approval or trust-update flows. This does not invalidate the old attestation by itself, so review `members/active` and remove stale `known_keys` entries separately when needed.

### When Private-Key Compromise Is Suspected

If you suspect compromise of your private key, SSH key, or machine, switch to a new key with the same basic flow as regular rotation: `key new` → `join` → `rewrap`. The important difference is that **you should not keep the old key around the way you might during a normal scheduled rotation**.

Create and share the new key first, then run `rewrap` after the PR is merged so recipients move to the new key. To limit further damage after suspected compromise, run `rewrap --rotate-key` if needed so the encrypted files are rebuilt with fresh content keys. Also rotate the actual secret values, such as API keys and passwords, if they may have been exposed through the compromised key.

Finally, remove the compromised old key from your local machine:

```bash
kapsaro key remove <compromised_old_kid>
```

This avoids leaving the leaked key on your machine as one of your retained old keys. During a normal scheduled rotation you may keep an old key for a while, but suspected compromise should be handled differently.

If the suspected compromise involves the SSH attestor key, removing it locally is not enough. In GitHub-backed workflows, **remove that SSH public key from GitHub as well**. That causes future online verification for keys backed by that SSH key to fail, which makes it easier to keep that key out of future approval flows.

### Content Key Rotation

Separately from member key rotation, you can also rotate the content keys (MK/DEK) of the encrypted files themselves. Use this when a member was removed or when you suspect leakage and want the files themselves rebuilt with fresh key material.

```bash
kapsaro rewrap --rotate-key
```

This regenerates the MK/DEK for all files, so old content keys no longer work against the new file versions. It does not erase plaintext that someone already decrypted and copied elsewhere.

### Activating a Specific Key

Use this when you have multiple local keys and want to switch which one will be used for future encryption and signing. This changes **only your local machine**; it does not update recipients in the workspace by itself.

```bash
kapsaro key activate <kid>
```

### Recommended Old Key Retention Period

Do not delete an old key too early. You may still need it to read older secrets or to bridge a transition period where not everyone has pulled the rewrapped data yet. Before deleting it, confirm:

- All team members have obtained encrypted files rewrapped with the new key
- No operations remain that require decrypting secrets encrypted with the old key

As a guideline, retain old keys for 1–3 months after rewrap completion.

---

## 13. CI/CD Integration

kapsaro supports CI/CD environments through portable private key export and environment variable-based key loading, **but only in trusted CI contexts**. This eliminates the need for SSH keys, `ssh-agent`, or a local keystore in CI runners.

### Overview

Read this chapter only if your CI system needs to **read secrets**. The intended model is not to manage keys or run `rewrap` from CI. Instead, create a dedicated CI key on a developer machine, give that key to CI securely, and use CI only for read-only commands such as `get`, `run`, or `decrypt`.

In CI environments, kapsaro reads the private key and password from environment variables instead of the local keystore. Environment variable-based key loading guarantees read-only commands: `run`, `decrypt`, `get`, and `list` are supported.

CI runners are usually temporary environments and do not keep a local trust store (`~/.config/kapsaro/trust/`). For trusted CI jobs that need to read secrets signed by other members, set `KAPSARO_STRICT_KEY_CHECKING=no`. This skips only read-path key approval checks that depend on your machine's saved approval history. Current member checks, recipient-label consistency checks, signer-recipient consistency checks, and signature verification still remain in place.

Even so, you should not treat the checked-out workspace as trusted by default. Limit environment variable-based key loading to jobs that run on trusted workflows, trusted refs, and trusted runners.

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

Only three things are needed in a trusted CI context. In other words, you do not need to reproduce a developer machine's SSH or local-keystore setup inside CI:

1. `KAPSARO_PRIVATE_KEY` environment variable — the exported private key (Base64url-encoded)
2. `KAPSARO_KEY_PASSWORD` environment variable — the password used during export
3. A workspace (Git repository containing `.kapsaro/` directory)

No `KAPSARO_HOME`, local keystore, SSH key, or config file is required.

If a trusted CI job has no local trust store and must run read commands against artifacts signed by other active members, set `KAPSARO_STRICT_KEY_CHECKING=no` only for that job. This skips read-path `known_keys` checks. It does not skip current member checks, recipient-label consistency checks, signer-recipient consistency checks, or signature verification, and it does not update the trust store without explicit review or approval.

### Setup Workflow

#### Step 1: Create a Dedicated CI Member

Create a dedicated member for CI (do not reuse a human member's key).

```bash
# On a developer machine with SSH key access
kapsaro key new --member-handle ci@example.com
kapsaro join --member-handle ci@example.com
```

#### Step 2: Add the CI Member to Recipients

```bash
git add .kapsaro/members/incoming/ci@example.com.json
git commit -m "Add CI member"
git push

# After merge: promote the incoming key and add the CI member to all encrypted files
kapsaro rewrap
git add .kapsaro/secrets/
git commit -m "Rewrap secrets for CI member"
git push
```

#### Step 3: Export the Private Key

```bash
# Run this on a developer machine with SSH signer and local keystore access
kapsaro key export --private --member-handle ci@example.com --out ci-key.txt
# You will be prompted to enter and confirm a password (minimum 20 UTF-8 bytes)
```

> Password strength: For offline brute-force resistance, the default export policy requires at least 20 UTF-8 bytes. If compatibility requires a password from 8 through 19 bytes, pass `--allow-weak-password` explicitly. The CLI still prints a warning in that mode, so a CI secret variable generated by a password manager is ideal.

The output file contains a single line of Base64url-encoded text. If you intentionally need stdout output, pass `--stdout` explicitly.

#### Step 4: Register in CI Secret Variables

Register two secret variables in your CI platform:

| Variable | Value |
|----------|-------|
| `KAPSARO_PRIVATE_KEY` | Contents of `ci-key.txt` |
| `KAPSARO_KEY_PASSWORD` | The password you entered during export |

After registering, securely delete the `ci-key.txt` file. Do not relay the private key through CI job logs, stdout, or ad-hoc artifacts.

#### Step 5: Use in CI Jobs

CI jobs can use only the secret-operation commands that already support environment variable-based key loading. The member handle is automatically determined from the private key.

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

      - name: Install kapsaro
        run: cargo install --path .

      - name: Run with secrets
        env:
          KAPSARO_PRIVATE_KEY: ${{ secrets.KAPSARO_PRIVATE_KEY }}
          KAPSARO_KEY_PASSWORD: ${{ secrets.KAPSARO_KEY_PASSWORD }}
          KAPSARO_STRICT_KEY_CHECKING: no
        run: kapsaro run -- ./deploy.sh
```

### Example: Generic CI Configuration

```bash
# Any CI platform with secret environment variables
export KAPSARO_PRIVATE_KEY="<registered secret>"
export KAPSARO_KEY_PASSWORD="<registered secret>"
export KAPSARO_STRICT_KEY_CHECKING=no

# Only commands supporting environment variable-based key loading work
kapsaro get DATABASE_URL
kapsaro run -- ./my-app
kapsaro decrypt ca.pem.encrypted --out ca.pem
```

### Supported Operations

At the moment, environment variable-based key loading supports only these read operations:

- **Decryption** (`run`, `decrypt`, `get`)
- **Listing** (`list`)

All other commands remain unavailable when loading keys via environment variables:

- **Secret mutation / re-signing** (`encrypt`, `set`, `unset`, `import`, `rewrap`)
- **Key lifecycle** (`key new`, `key list`, `key activate`, `key remove`, `key export`, `key export --private`)
- **Setup** (`init`, `join`)
- **Other helper commands** (`inspect`, `member`, `config`, etc.)

### Security Considerations

- **Password exposure**: `KAPSARO_KEY_PASSWORD` persists in process memory and may be visible via `/proc/*/environ` on Linux. This is consistent with how CI platforms handle secrets.
- **Trusted CI only**: Follow the allowed and forbidden CI contexts described earlier in this chapter. Attacker-controlled checkouts must not be used as signature-verification input.
- **Scope of `KAPSARO_STRICT_KEY_CHECKING=no`**: As described earlier in this chapter, this is an exception for CI jobs that cannot keep a local trust store. It has no effect on write commands and does not update local approval history without explicit review or approval. Non-interactive write commands fail before saving output when the output member set still needs review.
- **Dedicated CI member**: Use the dedicated CI member created in the setup steps; do not reuse a human member's key. This allows independent rotation and revocation.
- **Key rotation**: Re-export and secret-store updates should be done on a developer machine with SSH signer and local keystore access, just like the initial setup. Do not perform this inside CI jobs.
- **Least privilege**: Only add the CI member to the secrets it actually needs access to.

---

## 14. FAQ

### General

### Q: Is a server required?

No. kapsaro operates without a server. All core operations — encryption, decryption, signature verification — work entirely locally. Online verification via the GitHub API is an optional additional check.

### Q: Do I need GPG?

No. kapsaro works with SSH keys (Ed25519) only. No GPG or PGP key management required.

### Q: Do I need a cloud Secrets Manager?

No. Encryption, decryption, and key management all happen locally. There is no dependency on KMS or cloud services.

### Q: Do I need to manage a shared secret key for the team?

No. kapsaro uses public-key cryptography, so there is no shared secret key for the whole team. Secrets are encrypted separately for each member's public key, which removes the need to distribute, manage, or rotate a common password or shared key.

### Q: Is it safe to commit public key files to GitHub?

Yes. `members/active/*.json` contains public keys (the encryption public key and the SSH public key fingerprint), but no private keys whatsoever. Public keys are, by definition, safe to share publicly.

Decrypting secrets requires the private key stored locally at `~/.config/kapsaro/keys/`. This private key is never included in Git.

### Q: Is it safe to make the repository public if secrets are encrypted?

Encrypted files are protected by strong modern cryptography, so decryption without the private key is extremely difficult. That said, making a repository public still carries operational risks beyond the cryptography itself. For highly sensitive data, keeping the repository private is recommended.

### SSH Keys

### Q: Do I need to create a new SSH key?

If you already have an Ed25519 key (e.g., for GitHub), you can reuse it. Otherwise, generate one with `ssh-keygen -t ed25519`. RSA and other key types are not supported.

### Q: Why is the SSH agent needed?

kapsaro private keys are protected by an SSH Ed25519 key instead of a passphrase. Every kapsaro operation requires decryption using that SSH key, so using an SSH agent is convenient if you want to avoid entering credentials repeatedly.

In environments where an SSH agent is unavailable, you can switch to signing with the `ssh-keygen` command using the `--ssh-keygen` option.

When multiple keys are loaded in the SSH agent, you can explicitly specify which key to use with the `-i` option or the `ssh_identity` configuration:

```bash
kapsaro encrypt -i ~/.ssh/id_ed25519_work secret.env
```

### Q: Does it work with 1Password's SSH agent?

Yes. kapsaro supports signing via ssh-agent, including 1Password's SSH agent. See the [WSL User Guide](wsl_user_guide_en.md) for Windows/WSL2-specific configuration.

### Daily Usage

### Q: Can I migrate from an existing .env file?

Yes. `kapsaro import .env` imports everything at once. Then use `kapsaro run` to execute commands with decrypted secrets injected as environment variables.

### Q: Can I encrypt files other than .env?

Yes. Certificates, configuration files, and arbitrary binaries can be handled with `kapsaro encrypt` / `kapsaro decrypt`. See [Chapter 9](#9-file-encryption-and-decryption).

### Q: Can I manage multiple environments (dev / staging / prod)?

Yes. Use the `-n` option to create separate stores for each environment:

```bash
kapsaro set -n staging DATABASE_URL "postgres://..."
kapsaro set -n prod DATABASE_URL "postgres://..."
kapsaro run -n staging -- ./my-app
```

### Q: Should I use `kapsaro run` or manually load a `.env` file?

`kapsaro run` is recommended for these reasons:

- No plaintext `.env` file is left on disk
- The latest secrets are decrypted on each run, so value updates take effect immediately
- Signature verification runs automatically, preventing command execution with tampered secrets
- It reduces accidental leakage of arbitrary parent-shell environment variables into the child process

### Q: How do I manage separate secrets for multiple projects?

Each Git repository can have its own independent `.kapsaro/`. Run `kapsaro init` in each project to manage them as independent Workspaces.

Even if the same member participates in multiple projects, their public key is registered independently in each workspace.

### Q: Can I control sharing per encrypted file?

Not in the usual single-workspace setup. In kapsaro, encrypted files are shared with all members in that workspace's `members/active`.

If you need different sharing groups, the practical approach is to **use multiple workspaces**. Because you can switch the target workspace with `-w` / `--workspace`, you can operate separate workspaces for groups such as "whole development team," "production operators only," or "members of one specific project." In that model, the workspace itself becomes the sharing group.

This is a more exceptional operating pattern, so it is easier to think in terms of one workspace for one shared team by default. Consider splitting workspaces only when you clearly need different sharing scopes.

### Q: What happens if encrypted files conflict in Git?

kapsaro encrypts each `.env` key individually, so changes to different keys rarely conflict. If the same key is modified simultaneously, resolve the conflict by choosing one side, just like any other Git conflict.

### Membership and Keys

### Q: Does removing a member erase past secrets?

No. Removing a member and running rewrap does not eliminate values that member has already decrypted — those values may still exist on their machine.

To eliminate the risk of exposure after removal, always rotate the values (API keys, passwords, etc.) the member may have known.

### Q: Is key rotation supported?

Yes. `kapsaro rewrap --rotate-key` regenerates encryption keys and re-encrypts everything. This supports both member changes and periodic rotation. See [Chapter 12](#12-key-management-and-rotation).

### Q: Does it work in CI/CD environments?

Yes. `kapsaro run` and `kapsaro get` work non-interactively via environment variable-based key loading. See [Chapter 13](#13-cicd-integration) for setup details, allowed contexts, and security considerations.

### Troubleshooting

### Q: SSH agent errors — "no keys" or "agent not running"

Run `ssh-add -l` to check. If empty, add your key with `ssh-add ~/.ssh/id_ed25519`. If the agent is not running, start it with `eval "$(ssh-agent -s)"`.

### Q: "Key expired" warnings or errors

Keys expire one year after generation by default. Follow the rotation procedure in [Chapter 12](#12-key-management-and-rotation): generate a new key with `kapsaro key new`, stage it with `kapsaro join`, then run `kapsaro rewrap` after the PR is merged.

If `decrypt`, `get`, `run`, `list`, `set`, `unset`, `import`, `rewrap`, or `member remove` fails with `E_KEY_EXPIRED`, normally finish rotation and `rewrap` first. If you need emergency recovery for older secrets, pass `--allow-expired-key` to that command. To allow several commands temporarily, set `KAPSARO_ALLOW_EXPIRED_KEY=yes` only for that shell or CI step, or use `kapsaro config set allow_expired_key yes` only with a clear plan to set it back afterward.

`member verify --approve` does not approve expired PublicKeys. `--allow-expired-key` and `KAPSARO_ALLOW_EXPIRED_KEY=yes` do not save expired member keys to the local trust store.

### Q: Unexpected approval prompts when decrypting

This occurs when the signer's `kid` or an active recipient `kid` in the artifact has not been reviewed on your machine. Run `kapsaro member verify --approve` to review and approve current active members. If a read command warns that a recipient kid is no longer in `members/active`, the artifact may still contain stale recipient metadata. Run `kapsaro rewrap` before writing it.

### Q: "Non-deterministic SSH signature" error

This means your SSH key produced different signatures for the same input on two consecutive attempts. This can happen with FIDO2/hardware tokens (Ed25519-SK). kapsaro requires deterministic Ed25519 signatures. Use a standard software Ed25519 key instead.

---

## 15. Command Reference

### Common Option Groups

Accepted options differ by command. These options are shared by multiple commands.

| Option | Description |
|--------|-------------|
| `--home <path>` | Specify the local kapsaro state directory (default: `~/.config/kapsaro/`) |
| `-w` / `--workspace <path>` | Specify Workspace Root |
| `-m` / `--member-handle <handle>` | Specify the member handle to use |
| `-i` / `--ssh-identity <path>` | Specify SSH key file path. Also used for key selection with ssh-agent |
| `--ssh-agent` | Use ssh-agent for SSH signing |
| `--ssh-keygen` | Use the ssh-keygen command for SSH signing |
| `--json` | Output JSON for commands that support it |
| `-q` / `--quiet` | Suppress success and status messages for commands that support it |
| `-v` / `--verbose` | Show command-specific verbose output |
| `--debug` | Show internal debug trace logs |
| `-n` / `--name <name>` | Select a KV store name (default: `default`) |
| `-f` / `--force` | Skip confirmation for commands that support it |
| `--allow-expired-key` | Explicitly allow recovery decryption and operational artifact signature verification with expired keys for commands that support it |

### Initialization and Joining

| Command | Description |
|---------|-------------|
| `kapsaro init [-m <handle>] [-w <path>] [--github-user <login>]` | Bootstrap a new Workspace and register the first member in active |
| `kapsaro join [-m <handle>] [-w <path>] [--github-user <login>] [--force]` | Request to join an existing Workspace or stage a rotated key in incoming |

### KV Operations

| Command | Description |
|---------|-------------|
| `kapsaro set [-n <name>] [-m <handle>] [--allow-expired-key] <KEY> <VALUE>` | Add or update an entry |
| `kapsaro set [-n <name>] [-m <handle>] [--allow-expired-key] <KEY> --stdin` | Read value from stdin and set it |
| `kapsaro get [-n <name>] [-m <handle>] [--allow-expired-key] [--allow-non-member] <KEY>` | Retrieve and display a specific key's value |
| `kapsaro get [-n <name>] [-m <handle>] [--allow-expired-key] [--allow-non-member] --all` | Retrieve and display all entries |
| `kapsaro get [-n <name>] [--all] [--allow-non-member] --with-key` | Output in `KEY="VALUE"` format |
| `kapsaro unset [-n <name>] [-m <handle>] [--allow-expired-key] <KEY> [--force]` | Remove an entry. Non-interactive use requires `--force` |
| `kapsaro list [-n <name>] [-m <handle>] [--allow-expired-key] [--allow-non-member] [--json]` | List key names (values not displayed) |
| `kapsaro import [-n <name>] [-m <handle>] [--allow-expired-key] <file> [--json]` | Bulk import a `.env` file |
| `kapsaro run [-n <name>] [-m <handle>] [--allow-expired-key] -- <command> [args...]` | Run a command with secrets injected as environment variables |

### File Operations

| Command | Description |
|---------|-------------|
| `kapsaro encrypt [-m <handle>] <file> [--out <path> \| --stdout]` | Encrypt a file (file-enc) |
| `kapsaro encrypt [-m <handle>] --stdin (--out <path> \| --stdout)` | Encrypt stdin input as file-enc |
| `kapsaro decrypt [-m <handle>] [--kid <kid>] [--allow-expired-key] [--allow-non-member] <file> (--out <path> \| --stdout)` | Decrypt a file |
| `kapsaro decrypt [-m <handle>] [--kid <kid>] [--allow-expired-key] [--allow-non-member] --stdin (--out <path> \| --stdout)` | Read file-enc JSON from stdin and decrypt it |
| `kapsaro inspect <file> [--json] [--verbose]` | Display encrypted file metadata (no decryption needed) |

### Diagnostics

| Command | Description |
|---------|-------------|
| `kapsaro doctor [-w <path>] [--home <path>] [-m <handle>] [--json] [--verbose] [--debug]` | Run read-only health checks for workspace structure, members, local trust state, encrypted artifacts, and CI environment-key readiness |

### Member Management

| Command | Description |
|---------|-------------|
| `kapsaro member list [--json] [--verbose]` | List all members and each `kid` |
| `kapsaro member show <member_handle> [--json] [--verbose]` | Show details for a specific member |
| `kapsaro member verify [-m <handle>] [--approve] [<member_handle>...] [--json]` | Verify active member public keys and optionally save approvals in the local trust store |
| `kapsaro member add <file> [--force]` | Add a member's public key file to incoming |
| `kapsaro member remove <member_handle> [--force] [--allow-expired-key]` | Remove a member from the Workspace. Non-interactive use requires `--force` |
| `kapsaro rewrap [-m <handle>] [--allow-expired-key] [--allow-non-member] [--rotate-key] [--clear-disclosure-history] [--target <path>...] [--json]` | Activate pending members and update recipient information in encrypted files |

When `--target` is omitted, `rewrap` processes all encrypted files in the workspace. When `--target` is provided, only the specified files are processed.

### Local Trust Store

| Command | Description |
|---------|-------------|
| `kapsaro trust keys list [-m <handle>] [--json] [--verbose]` | List approved keys saved in the local trust store |
| `kapsaro trust keys remove [-m <handle>] <kid>` | Remove the approval record for a specific key from the local trust store |
| `kapsaro trust keys purge [-m <handle>] --older-than <duration> [--force]` | Remove key approval records older than the given duration |
| `kapsaro trust recipients list [-m <handle>] [--json] [--verbose]` | List reviewed artifact member sets saved in the local trust store |
| `kapsaro trust recipients remove [-m <handle>] <sid>` | Remove the review record for a specific artifact member set |
| `kapsaro trust recipients purge [-m <handle>] --older-than <duration> [--force]` | Remove artifact member set review records older than the given duration |

### Key Management

| Command | Description |
|---------|-------------|
| `kapsaro key new [-m <handle>] [--github-user <login>] [--no-activate] [--expires-at <datetime> \| --valid-for <duration>]` | Generate a new key. The generated key becomes active by default |
| `kapsaro key list [-m <handle>] [--json] [--verbose]` | List keys |
| `kapsaro key activate [-m <handle>] [<kid>]` | Activate a specific key. If `kid` is omitted, the newest valid key is selected |
| `kapsaro key remove [-m <handle>] <kid> [--force]` | Remove a key. Removing the active key requires `--force` |
| `kapsaro key export [-m <handle>] [<kid>] --out <path>` | Export public key |
| `kapsaro key export --private [-m <handle>] [<kid>] [--allow-weak-password] (--stdout \| --out <path>)` | Export private key (password-protected, for CI/CD) |

### Configuration

| Command | Description |
|---------|-------------|
| `kapsaro config set <key> <value>` | Set a configuration value |
| `kapsaro config get <key>` | Get a configuration value |
| `kapsaro config list` | List all configuration values |
| `kapsaro config unset <key>` | Remove a configuration value |

Configuration commands do not require a workspace. They operate on the global config file.

Configuration keys: `member_handle`, `workspace`, `ssh_signing_method` (`auto` / `ssh-agent` / `ssh-keygen`), `ssh_identity`, `ssh_keygen_command`, `ssh_add_command`, `github_user`, `allow_expired_key`, `allow_non_member`

---

## 16. Configuration Reference

### Common Optional Configuration

You only need these settings if you want to avoid typing the same options repeatedly. They are not required during initial installation.

```bash
# Set default member handle (allows omitting --member-handle going forward)
kapsaro config set member_handle alice@example.com

# Set GitHub account (for online verification)
kapsaro config set github_user alice-gh

# Set default workspace (useful when running outside the Git repository)
kapsaro config set workspace ~/src/project/.kapsaro

# Set SSH signing method (default "auto" works for most cases)
# auto: tries ssh-agent first, then ssh-keygen
# ssh-agent: use SSH agent
# ssh-keygen: use ssh-keygen command
kapsaro config set ssh_signing_method auto

# Set SSH key (select a specific key when multiple keys are loaded in ssh-agent)
kapsaro config set ssh_identity ~/.ssh/id_ed25519_work

# Keep expired-key recovery disabled unless you are doing emergency recovery
kapsaro config set allow_expired_key no

# Keep non-member signer acceptance disabled unless you are reviewing one artifact
kapsaro config set allow_non_member no
```

The configuration file is located at `~/.config/kapsaro/config.toml`.

kapsaro resolves configuration values from multiple sources in the following priority order:

1. **CLI options** (highest priority)
2. **Environment variables**
3. **Config file** (`<KAPSARO_HOME>/config.toml`)
4. **Default values** (lowest priority)

When a higher-priority source provides a value, lower-priority sources are ignored.

Workspace Root is resolved in this order: `--workspace`, `KAPSARO_WORKSPACE`, `workspace` in the config file, then automatic detection from the current directory.

### Config File

The global config file is located at `<KAPSARO_HOME>/config.toml` (default: `~/.config/kapsaro/config.toml`). It uses flat TOML key-value format.

| Key | Description | Default | CLI Option | Environment Variable |
|-----|-------------|---------|------------|---------------------|
| `member_handle` | Default member handle (pattern: `^[A-Za-z0-9][A-Za-z0-9._@+-]{0,253}$`) | (none) | `-m` / `--member-handle` | `KAPSARO_MEMBER_HANDLE` |
| `workspace` | Default Workspace Root path. Supports tilde expansion (`~/...`) | (none; auto-detected when unset) | `-w` / `--workspace` | `KAPSARO_WORKSPACE` |
| `ssh_identity` | Path to SSH private key file (Ed25519). Supports tilde expansion (`~/...`) | `~/.ssh/id_ed25519` | `-i` / `--ssh-identity` | `KAPSARO_SSH_IDENTITY` |
| `ssh_signing_method` | SSH signing method: `auto`, `ssh-agent`, `ssh-keygen` | `auto` | `--ssh-agent` / `--ssh-keygen` | `KAPSARO_SSH_SIGNING_METHOD` |
| `ssh_keygen_command` | Path to `ssh-keygen` command | `ssh-keygen` | — | — |
| `ssh_add_command` | Path to `ssh-add` command | `ssh-add` | — | — |
| `github_user` | Default GitHub login name for `key new` | (none) | `--github-user` | `KAPSARO_GITHUB_USER` |
| `allow_expired_key` | Whether to allow recovery decryption and operational artifact signature verification with expired keys. Value is `yes` or `no` | `no` | `--allow-expired-key` | `KAPSARO_ALLOW_EXPIRED_KEY` |
| `allow_non_member` | Whether to enable the one-shot interactive confirmation flow for artifacts signed by non-members. Value is `yes` or `no` | `no` | `--allow-non-member` | `KAPSARO_ALLOW_NON_MEMBER` |

Example:

```toml
member_handle = "alice@example.com"
workspace = "~/src/project/.kapsaro"
ssh_identity = "~/.ssh/id_ed25519"
ssh_signing_method = "auto"
github_user = "alice-gh"
allow_expired_key = "no"
allow_non_member = "no"
```

If the config file does not exist, kapsaro falls back to environment variables and default values without error. If the file exists but contains syntax errors, kapsaro reports an error. `config get`, `config set`, `config unset`, and `config list` operate on the global config file and do not check whether the configured workspace exists.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `KAPSARO_HOME` | Base directory for kapsaro configuration and keys | `~/.config/kapsaro/` |
| `KAPSARO_MEMBER_HANDLE` | Default member handle | (none) |
| `KAPSARO_SSH_IDENTITY` | Path to SSH private key file (Ed25519) | `~/.ssh/id_ed25519` |
| `KAPSARO_SSH_SIGNING_METHOD` | SSH signing method: `auto`, `ssh-agent`, `ssh-keygen` | `auto` |
| `KAPSARO_GITHUB_USER` | Default GitHub login name for `key new` | (none) |
| `KAPSARO_WORKSPACE` | Workspace directory path (overrides auto-detection) | (auto-detected) |
| `KAPSARO_STRICT_KEY_CHECKING` | Whether to check local approval history during read operations: `yes`, `no` | `yes` |
| `KAPSARO_ALLOW_EXPIRED_KEY` | Whether to allow recovery decryption and operational artifact signature verification with expired keys: `yes`, `no` | `no` |
| `KAPSARO_ALLOW_NON_MEMBER` | Whether to enable the one-shot interactive confirmation flow for artifacts signed by non-members: `yes`, `no` | `no` |
| `KAPSARO_PRIVATE_KEY` | Base64url-encoded portable private key document (CI/CD) | (none) |
| `KAPSARO_KEY_PASSWORD` | Password for `KAPSARO_PRIVATE_KEY` (CI/CD) | (none) |

**Notes:**

- `KAPSARO_PRIVATE_KEY` and `KAPSARO_KEY_PASSWORD` are used together for CI/CD environments where a local keystore is not available. When `KAPSARO_PRIVATE_KEY` is set, `KAPSARO_KEY_PASSWORD` is required. See [Chapter 13](#13-cicd-integration) for details.
- `KAPSARO_STRICT_KEY_CHECKING=no` skips only read-path local key approval checks. This is permitted only for read operations (decrypt, get, run, list). Write-path operations always enforce strict checking, including output artifact member set review.
- `KAPSARO_ALLOW_EXPIRED_KEY=yes` is not a way to return expired keys to normal use. Set it only for the target emergency recovery command or step, then unset it afterward.
- `KAPSARO_ALLOW_NON_MEMBER=yes` enables the one-shot non-member signer confirmation flow only for interactive `decrypt`, `get`, `list`, and `rewrap` runs. It has no effect for non-interactive execution or `run`.
- `KAPSARO_WORKSPACE` overrides automatic workspace detection. Useful when running commands outside the Git repository tree or when using a workspace outside the current directory.

---

*This guide covers what most users need for day-to-day kapsaro usage. If you need deeper design background, refer to the related design documents.*
