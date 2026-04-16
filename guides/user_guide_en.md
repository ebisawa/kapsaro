# secretenv User Guide

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
10. [Member Management](#10-member-management)
11. [Key Management and Rotation](#11-key-management-and-rotation)
12. [CI/CD Integration](#12-cicd-integration)
13. [FAQ](#13-faq)
14. [Command Reference](#14-command-reference)
15. [Configuration Reference](#15-configuration-reference)

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

secretenv is not a complete solution to every security problem. It does not automatically solve what happens after decryption, how to revoke values that were already seen, or how to protect compromised machines and keys. See [Chapter 4](#4-security-basics-for-users) for these assumptions and limits.

---

## 2. What to Know Before You Start

### Start with the big picture

It helps to think about secretenv in this order:

1. The team shares encrypted secrets and member information in a workspace inside the Git repository
2. Each user has their own public key and private key
3. New members and rotated keys are reviewed, then approved as secret recipients

The next sections explain the tool in that order.

### Share the workspace through Git

The workspace is the `.secretenv/` directory in your Git repository. This is where the team shares secrets and member information.

```
.secretenv/
├── members/
│   ├── active/
│   └── incoming/
├── secrets/
└── config.toml
```

- `members/active/`: public keys for current members
- `members/incoming/`: public keys waiting for approval or rotation
- `secrets/`: encrypted secrets

`.secretenv/` is part of normal operation, so do not add it to `.gitignore`.

### Understand the role of the keys first

Each user has their own key pair.

- A **public key** can be shared with the team
- A **private key** must stay with that user

The basic idea of public-key encryption is simple: **encrypt with a public key, decrypt with the matching private key**. In secretenv, secrets are encrypted for recipients' public keys, so only users with the matching private keys can decrypt them. In other words, it does not depend on securely distributing one team-wide shared secret key.

With shared-key encryption, everyone who needs access must somehow receive the same secret key securely, so **how to distribute that shared secret** becomes an operational problem in itself. With public-key encryption, you only distribute public keys, so you do not need to distribute the secret material that must remain private.

The important rule is that **a private key must never be shared with anyone else**. Giving someone your private key is effectively giving them the ability to read secrets as you. Do not commit it to Git, paste it into chat, or share it carelessly through backups or exports.

By contrast, **a public key is something you should actively share even though it is called a "key."** A public key alone normally cannot decrypt the secret. That is why it is safe to commit public-key files under `members/active/` or `members/incoming/`.

The difficult part is **knowing whose public key it really is**. A public key can be safe to share and still be falsely presented as "Alice's key" by an attacker. In practice, the hard problem is not distributing public keys, but deciding **which person a given public key should be trusted to represent**.

### How a member becomes usable

New members and rotated keys first go into `members/incoming/`. They become usable recipients only after an existing member reviews the PR and runs `secretenv rewrap`.

In practice, **PR review is part of member approval**. During review, you are not only checking that "a public key was added" but also deciding whether that key should be trusted as belonging to that person. Do not merge unfamiliar public keys casually.

### Two formats you will use most

- **kv-enc**: For `.env`-style key-value secrets. This is the recommended default for day-to-day use.
- **file-enc**: For encrypting an entire file such as a certificate or binary.

For operations, see [Chapter 8](#8-daily-usage-kv-store) and [Chapter 9](#9-file-encryption-and-decryption).

---

## 3. Common Terms

### Workspace

The workspace is the `.secretenv/` directory in a Git repository. When you run secretenv inside a Git repository, it usually finds the workspace automatically. Outside a Git repository, specify it explicitly with `-w` / `--workspace`.

### `active` / `incoming`

- **incoming**: A public key that is not approved yet
- **active**: An approved public key that can be a recipient of secrets

### `rewrap`

The operation that updates recipient information after a member change or key rotation. It is also what turns an `incoming` key into an active one.

### `member_id`

A string that identifies a member. It often looks like an email address, but it does not have to be a real email address. It only needs to be unique within the team.

### `kid`

An ID that identifies a key. A single member can have multiple keys, so `kid` tells you which one is being used. You will mostly see it in `key list` and `rewrap` output.

### Local trust store

The local record of approved keys under `~/.config/secretenv/trust/`. Commands such as `member verify --approve` store approvals there so you are not asked the same question repeatedly.

---

## 4. Security Basics for Users

### What secretenv protects

Secrets stored in Git are encrypted, and signatures are verified. Even if the repository is shared, the content cannot be read without the right private key.

### What secretenv does not automatically protect

- What legitimate members do after they decrypt a secret
- Copies or memories of values that were already seen
- Leakage of the local machine or private keys themselves

Removing a member does not erase secrets they already saw. If needed, rotate the secret values themselves.

### Role of the SSH key

The SSH Ed25519 key is not the key that directly decrypts workspace secrets. It is used to protect the local secretenv private key and to show which SSH key is backing that secretenv key.

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
- Generates your local key pair in the keystore
- Registers your public key at `members/active/alice@example.com.json`

If the workspace already exists with active members, `init` exits without changes. Use `join` to submit a key to an existing workspace.

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
An active member needs to run 'secretenv rewrap' so you can start reading secrets.
```

Unlike `init`, `join` does not create a Workspace — it only places your public key in `members/incoming/`. Existing active members can also use `join` after `key new` to stage a rotated key generation in `members/incoming/`.

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

# Encrypt from stdin and save to a file
cat certs/ca.pem | secretenv encrypt --stdin --out .secretenv/secrets/ca.pem.encrypted

# Encrypt from stdin and emit file-enc JSON to stdout
cat certs/ca.pem | secretenv encrypt --stdin --stdout > ca.pem.encrypted
```

A signature is attached automatically during encryption.

Batch `rewrap` automatically covers files under `.secretenv/secrets/` only when `--target` is not provided. If you want to rewrap only a specific file-enc artifact, use `secretenv rewrap --target <path>` so only the specified file is processed.

### Decrypting

```bash
# Signature verification is performed before decryption
secretenv decrypt ca.pem.encrypted --out certs/ca.pem
```

Do not manage decrypted plaintext files in Git. `.secretenv/` belongs in Git, but decrypted `.env` files, certificates, and other plaintext outputs should be covered by `.gitignore`.

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

## 10. Member Management

### Member Addition Git Workflow

When a new member submits a PR via `secretenv join`, follow this flow to approve them.

**Why PR review matters**: Reviewing and merging a PR is the decision to "trust this person's public key." Merging a PR from an unknown person without review means adding them as a recipient of your secrets.

```bash
# 1. After merging the new member's PR, pull the latest
git pull

# 2. Run rewrap and review the displayed key information
secretenv rewrap

# Example:
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
- Bob is added as a recipient in all encrypted files

**Recommended**: After rewrap, register the new member's key in your local trust store to avoid approval prompts on future operations:

```bash
secretenv member verify --approve
```

When incoming members exist, `rewrap` asks for interactive approval. Review the displayed key information and approve it only after deciding that the public key really belongs to that person. If there are no incoming members, `rewrap` usually runs non-interactively because it only needs to synchronize recipient data.

Also note that `rewrap` is not supported when CI/CD uses environment variable-based key loading. Run `rewrap` on a developer machine.

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

`member verify --approve` is the command you use to review the keys of current active members and save the result on your machine. The command shows identifying information for each key so you can decide whether "this public key really belongs to this person" before approving it. Approved keys are stored in your local trust store, so later operations no longer need to ask for the same confirmation again.

### Managing the Local Trust Store

The local trust store is **where your machine remembers which public keys you have already reviewed and approved**. When an approved key is stored there, later decrypt or verification operations do not need to ask you the same question every time.

`trust list` shows the approved keys currently saved on your machine. `trust remove` and `trust purge` delete those local records. The local trust store basically grows over time as approvals accumulate, so these commands are useful when you want to clean up entries that are no longer relevant, remove keys that are no longer used, or force yourself to review a key again.

In normal use, approvals are usually recorded automatically through `member verify --approve` or interactive approval flows, so you do not need to manage the trust store manually every day. Use these commands when you want to undo an approval, clean up old approvals, or force yourself to review a key again from scratch.

```bash
# List approved keys
secretenv trust list

# Remove one kid from the local trust store
secretenv trust remove <kid>

# Purge old approvals in bulk
secretenv trust purge --older-than 180d --force
```

`trust remove` and `trust purge` change **only the records on your own machine**. They do not modify workspace membership or recipients in encrypted files. In other words, these commands do not change who is in the team; they change how much you will be asked to re-confirm on later operations.

### Removing Members

Use this when you no longer want a member to read future versions of your secrets: for example when someone leaves the team, changes role, loses a device, or should otherwise lose access. Think of it as a two-step process. First, `member remove` takes the member out of the workspace member list. Then `rewrap` updates the encrypted files themselves. After that, the removed member can no longer decrypt the **updated** secrets.

**Important**: Removing a member and running rewrap **does not invalidate secret values that member previously obtained**. It is cryptographically impossible to "revoke past disclosures."

```bash
# 1. Remove the member from the workspace member list
secretenv member remove alice@example.com

# 2. Update recipient information in encrypted files
secretenv rewrap

# 3. Commit the change
git add .secretenv/
git commit -m "Remove alice from secretenv"
```

At this point, what has changed is **future access**. The secret values themselves have not changed yet, so you still need the follow-up work below.

### Required Steps After Removal

Removing the member and running `rewrap` is not enough by itself. Any values the removed member may already know should be changed if they still matter.

```bash
secretenv set API_KEY "new-api-key"
secretenv set DATABASE_PASSWORD "new-password"
```

Then use `secretenv inspect` to see which files still show disclosure history for that member. This helps you decide which secrets need rotation.

After you finish updating the values, you can clear the disclosure history if needed.

```bash
secretenv rewrap --clear-disclosure-history
```

In practice, member removal is not complete until you have handled the **secret values that person may already know**, not just the membership records. At the same time, review access in the real services outside secretenv as well, such as GitHub, AWS, databases, and SaaS tools.

---

## 11. Key Management and Rotation

This chapter is about keeping your own keys usable and safe over time. You will mostly come here when a key is nearing expiration, when compromise is suspected, or when you want to clean up old keys.

### Key Management Principles

At minimum, follow these rules:

- **Public keys may be shared, private keys must not**: only public keys belong in PRs. Private keys stay in your local `~/.config/secretenv/keys/` and must not be committed to Git or sent through chat
- **You are also responsible for the SSH key that protects the private key**: the secretenv private key is protected by your SSH Ed25519 key, so careless copying or use on unsafe machines is a real risk
- **Device security is part of key management**: screen lock, disk encryption, account protection, and backup hygiene all matter because they protect the keys indirectly
- **Rotate immediately if compromise or loss is suspected**: if your private key, SSH key, or machine may be unsafe, run `key new` → `join` → `rewrap` and rotate secret values when needed

### Key States

| State | Description |
|-------|-------------|
| active | Key used for encryption and signing. One per member_id. |
| available | Can decrypt but is not used for encryption or signing. |
| expired | Past expiration date. Can still decrypt (with a warning). |

In everyday use, only the `active` key is used for new encryption and signing. `available` or `expired` keys may still remain because older secrets may still need them for decryption.

### Listing Keys

```bash
secretenv key list
```

Use `key list` when you want to check which key is currently active, whether old keys are still present, or whether an expiration date is approaching. It is a good first step before rotation or cleanup.

The CLI may show kids with hyphens, but commands such as `key activate`, `key remove`, and `key export` accept both hyphenated and non-hyphenated input.

### Regular Rotation

Rotation is not only for scheduled expiry. You should also rotate when compromise of the private key or the protecting SSH key is suspected. The high-level flow is: create a new key, share the new public key with the team, then update secret recipients to use it.

Keys expire one year after generation by default. Warnings appear starting 30 days before expiration.

**Summary**: (1) `key new` → (2) `join` → (3) PR and merge → (4) `rewrap` → (5) commit → (6) remove old key after transition period.

```bash
# 1. Generate a new local key (it becomes active automatically)
secretenv key new

# Specify an expiration date
secretenv key new --expires-at 2028-01-01T00:00:00Z
secretenv key new --valid-for 2y    # 2 years
secretenv key new --valid-for 180d  # 180 days

# 2. Submit the new public key to the workspace
secretenv join

# 3. Create a PR and get it reviewed/merged
git add .secretenv/members/incoming/alice@example.com.json
git commit -m "Rotate alice's key"
git push

# 4. After merge, switch secret recipient data to the new key
secretenv rewrap

# 5. Commit that change
git add .secretenv/secrets/
git commit -m "Rewrap secrets for alice's new key"
git push

# 6. Keep the old key for a while, then remove it later
secretenv key remove <old_kid>
```

The important point is that `key new` alone changes only your local machine. The workspace does not start using the new key until you share it with `join` and update recipients with `rewrap`.

If your team relies on GitHub online verify, it is useful to **remove the old SSH public key from GitHub after the migration is complete**. Online verify checks whether the key is registered on GitHub now, so deleting the old SSH key makes old attestations backed by that SSH key less likely to pass future approval or trust-update flows. This does not invalidate the old attestation by itself, so review `members/active` and remove stale `known_keys` entries separately when needed.

### When Private-Key Compromise Is Suspected

If you suspect compromise of your private key, SSH key, or machine, switch to a new key with the same basic flow as regular rotation: `key new` → `join` → `rewrap`. The important difference is that **you should not keep the old key around the way you might during a normal scheduled rotation**.

Create and share the new key first, then run `rewrap` after the PR is merged so recipients move to the new key. To limit further damage after suspected compromise, run `rewrap --rotate-key` if needed so the encrypted files are rebuilt with fresh content keys. Also rotate the actual secret values, such as API keys and passwords, if they may have been exposed through the compromised key.

Finally, remove the compromised old key from your local machine:

```bash
secretenv key remove <compromised_old_kid>
```

This avoids leaving the leaked key on your machine as one of your retained old keys. During a normal scheduled rotation you may keep an old key for a while, but suspected compromise should be handled differently.

If the suspected compromise involves the SSH attestor key, removing it locally is not enough. In GitHub-backed workflows, **remove that SSH public key from GitHub as well**. That causes future online verification for keys backed by that SSH key to fail, which makes it easier to keep that key out of future approval flows.

### Content Key Rotation

Separately from member key rotation, you can also rotate the content keys (MK/DEK) of the encrypted files themselves. Use this when a member was removed or when you suspect leakage and want the files themselves rebuilt with fresh key material.

```bash
secretenv rewrap --rotate-key
```

This regenerates the MK/DEK for all files, so old content keys no longer work against the new file versions. It does not erase plaintext that someone already decrypted and copied elsewhere.

### Activating a Specific Key

Use this when you have multiple local keys and want to switch which one will be used for future encryption and signing. This changes **only your local machine**; it does not update recipients in the workspace by itself.

```bash
secretenv key activate <kid>
```

### Recommended Old Key Retention Period

Do not delete an old key too early. You may still need it to read older secrets or to bridge a transition period where not everyone has pulled the rewrapped data yet. Before deleting it, confirm:

- All team members have obtained encrypted files rewrapped with the new key
- No operations remain that require decrypting secrets encrypted with the old key

As a guideline, retain old keys for 1–3 months after rewrap completion.

---

## 12. CI/CD Integration

secretenv supports CI/CD environments through portable private key export and environment variable-based key loading, **but only in trusted CI contexts**. This eliminates the need for SSH keys, `ssh-agent`, or a local keystore in CI runners.

### Overview

Read this chapter only if your CI system needs to **read secrets**. The intended model is not to manage keys or run `rewrap` from CI. Instead, create a dedicated CI key on a developer machine, give that key to CI securely, and use CI only for read-only commands such as `get`, `run`, or `decrypt`.

In CI environments, secretenv reads the private key and password from environment variables instead of the local keystore. Environment variable-based key loading guarantees read-only commands: `run`, `decrypt`, `get`, and `list` are supported.

CI runners are usually temporary environments and do not keep a local trust store (`~/.config/secretenv/trust/`). For trusted CI jobs that need to read secrets signed by other members, set `SECRETENV_STRICT_KEY_CHECKING=no`. This skips only the check that depends on your machine's saved approval history; current member checks and signature verification still remain in place.

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

1. `SECRETENV_PRIVATE_KEY` environment variable — the exported private key (Base64url-encoded)
2. `SECRETENV_KEY_PASSWORD` environment variable — the password used during export
3. A workspace (Git repository containing `.secretenv/` directory)

No `SECRETENV_HOME`, local keystore, SSH key, or config file is required.

If a trusted CI job has no local trust store and must run read commands against artifacts signed by other active members, set `SECRETENV_STRICT_KEY_CHECKING=no` only for that job. This skips only the local approval-history check. It does not skip current member checks, does not skip signature verification, and does not auto-update the trust store.

### Setup Workflow

#### Step 1: Create a Dedicated CI Member

Create a dedicated member for CI (do not reuse a human member's key).

```bash
# On a developer machine with SSH key access
secretenv key new --member-id ci@example.com
secretenv join --member-id ci@example.com
```

#### Step 2: Add the CI Member to Recipients

```bash
git add .secretenv/members/incoming/ci@example.com.json
git commit -m "Add CI member"
git push

# After merge: promote the incoming key and add the CI member to all encrypted files
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

At the moment, environment variable-based key loading supports only these read operations:

- **Decryption** (`run`, `decrypt`, `get`)
- **Listing** (`list`)

All other commands remain unavailable when loading keys via environment variables:

- **Secret mutation / re-signing** (`encrypt`, `set`, `unset`, `import`, `rewrap`)
- **Key lifecycle** (`key new`, `key list`, `key activate`, `key remove`, `key export`, `key export --private`)
- **Setup** (`init`, `join`)
- **Other helper commands** (`inspect`, `member`, `config`, etc.)

### Security Considerations

- **Password exposure**: `SECRETENV_KEY_PASSWORD` persists in process memory and may be visible via `/proc/*/environ` on Linux. This is consistent with how CI platforms handle secrets.
- **Trusted CI only**: Use environment variable-based key loading only in trusted workflow / trusted ref / trusted runner contexts. Attacker-controlled checkouts must not be used as signature-verification input.
- **Scope of `SECRETENV_STRICT_KEY_CHECKING=no`**: This is an exception for CI jobs that cannot keep a local trust store. It has no effect on write commands and does not auto-update local approval history.
- **Dedicated CI member**: Always use a dedicated CI member rather than a human member's key. This allows independent rotation and revocation.
- **Key rotation**: Rotate the CI member key and re-export with `key export --private` on a developer machine with SSH signer and local keystore access, then update the CI platform's secret store.
- **Least privilege**: Only add the CI member to the secrets it actually needs access to.

---

## 13. FAQ

### General

### Q: Is a server required?

No. secretenv operates without a server. All core operations — encryption, decryption, signature verification — work entirely locally. Online verification via the GitHub API is an optional additional check.

### Q: Do I need GPG?

No. secretenv works with SSH keys (Ed25519) only. No GPG or PGP key management required.

### Q: Do I need a cloud Secrets Manager?

No. Encryption, decryption, and key management all happen locally. There is no dependency on KMS or cloud services.

### Q: Do I need to manage a shared secret key for the team?

No. secretenv uses public-key cryptography, so there is no shared secret key for the whole team. Secrets are encrypted separately for each member's public key, which removes the need to distribute, manage, or rotate a common password or shared key.

### Q: Is it safe to commit public key files to GitHub?

Yes. `members/active/*.json` contains public keys (the encryption public key and the SSH public key fingerprint), but no private keys whatsoever. Public keys are, by definition, safe to share publicly.

Decrypting secrets requires the private key stored locally at `~/.config/secretenv/keys/`. This private key is never included in Git.

### Q: Is it safe to make the repository public if secrets are encrypted?

Encrypted files are protected by strong modern cryptography, so decryption without the private key is extremely difficult. That said, making a repository public still carries operational risks beyond the cryptography itself. For highly sensitive data, keeping the repository private is recommended.

### SSH Keys

### Q: Do I need to create a new SSH key?

If you already have an Ed25519 key (e.g., for GitHub), you can reuse it. Otherwise, generate one with `ssh-keygen -t ed25519`. RSA and other key types are not supported.

### Q: Why is the SSH agent needed?

secretenv private keys are protected by an SSH Ed25519 key instead of a passphrase. Every secretenv operation requires decryption using that SSH key, so using an SSH agent is convenient if you want to avoid entering credentials repeatedly.

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

Even if the same member participates in multiple projects, their public key is registered independently in each workspace.

### Q: Can I control sharing per encrypted file?

Not in the usual single-workspace setup. In secretenv, encrypted files are shared with all members in that workspace's `members/active`.

If you need different sharing groups, the practical approach is to **use multiple workspaces**. Because you can switch the target workspace with `-w` / `--workspace`, you can operate separate workspaces for groups such as "whole development team," "production operators only," or "members of one specific project." In that model, the workspace itself becomes the sharing group.

This is a more exceptional operating pattern, so it is easier to think in terms of one workspace for one shared team by default. Consider splitting workspaces only when you clearly need different sharing scopes.

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

Keys expire one year after generation by default. Follow the rotation procedure in [Chapter 11](#11-key-management-and-rotation): generate a new key with `secretenv key new`, stage it with `secretenv join`, then run `secretenv rewrap` after the PR is merged.

### Q: Unexpected approval prompts when decrypting

This occurs when the signer's `kid` is not in your local trust store. Run `secretenv member verify --approve` to review and approve current active members. See [Chapter 10](#10-member-management) for details.

### Q: "Non-deterministic SSH signature" error

This means your SSH key produced different signatures for the same input on two consecutive attempts. This can happen with FIDO2/hardware tokens (Ed25519-SK). secretenv requires deterministic Ed25519 signatures. Use a standard software Ed25519 key instead.

---

## 14. Command Reference

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
| `secretenv init [--member-id <id>]` | Bootstrap a new Workspace and register the first member in active |
| `secretenv join [--member-id <id>] [--force]` | Request to join an existing Workspace or stage a rotated key (added to incoming) |

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
| `secretenv encrypt <file> [--out <path> \| --stdout]` | Encrypt a file (file-enc) |
| `secretenv encrypt --stdin (--out <path> \| --stdout)` | Encrypt stdin input as file-enc |
| `secretenv decrypt <file> --out <path>` | Decrypt a file |
| `secretenv inspect <file>` | Display encrypted file metadata (no decryption needed) |

### Member Management

| Command | Description |
|---------|-------------|
| `secretenv member list` | List all members |
| `secretenv member show <member_id>` | Show details for a specific member |
| `secretenv member verify [<member_id>...]` | Verify active member public keys (with online verification) |
| `secretenv member verify --approve [<member_id>...]` | Review active member keys and save the approval result in the local trust store |
| `secretenv member add <file>` | Add a member's public key file to incoming |
| `secretenv member remove <member_id>` | Remove a member from the Workspace |
| `secretenv rewrap [--rotate-key] [--clear-disclosure-history] [--target <path>...]` | Activate pending members and update recipient information in all workspace encrypted files when `--target` is omitted, or only the specified target files when it is provided |

### Local Trust Store

| Command | Description |
|---------|-------------|
| `secretenv trust list` | List approved keys saved in the local trust store |
| `secretenv trust remove <kid>` | Remove the approval record for a specific key from the local trust store |
| `secretenv trust purge --older-than <duration> [-f, --force]` | Remove approval records older than the given duration from the local trust store |

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

## 15. Configuration Reference

### Common Optional Configuration

You only need these settings if you want to avoid typing the same options repeatedly. They are not required during initial installation.

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
| `SECRETENV_STRICT_KEY_CHECKING` | Whether to check local approval history during read operations: `yes`, `no` | `yes` |
| `SECRETENV_PRIVATE_KEY` | Base64url-encoded portable private key document (CI/CD) | (none) |
| `SECRETENV_KEY_PASSWORD` | Password for `SECRETENV_PRIVATE_KEY` (CI/CD) | (none) |

**Notes:**

- `SECRETENV_PRIVATE_KEY` and `SECRETENV_KEY_PASSWORD` are used together for CI/CD environments where a local keystore is not available. When `SECRETENV_PRIVATE_KEY` is set, `SECRETENV_KEY_PASSWORD` is required. See [Chapter 12](#12-cicd-integration) for details.
- `SECRETENV_STRICT_KEY_CHECKING=no` skips only the local approval-history check during read operations. This is permitted only for read operations (decrypt, get, run, list). Write-path operations always enforce strict checking.
- `SECRETENV_WORKSPACE` overrides the automatic workspace detection from the git repository root. Useful when running commands outside the repository tree.

---

*This guide covers what most users need for day-to-day secretenv usage. If you need deeper design background, refer to the related design documents.*
