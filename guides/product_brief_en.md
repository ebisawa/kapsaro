# SecretEnv: Share Encrypted `.env` Files Through Git

How does your team share `.env` files, certificates, and private key files today?

SecretEnv is an offline-first CLI for sharing secrets through a Git repository without storing them in plaintext. It works for both `.env`-style key-value files and arbitrary files such as certificates or config files, and it lets you manage membership and key updates through the same Git review flow your team already uses.

## Common Problems

### Sending `.env` Files Through Slack or DMs

- Plaintext secrets remain in message history and on local machines
- It becomes unclear who has the latest version
- Former team members may continue holding old values
- It is hard to track who changed what and when

### `.env.example` with Manual Secret Sharing

- Onboarding always requires someone to gather and hand over secrets
- Environment drift causes issues that only appear in staging or CI
- New keys and updates are easy to miss

### Dedicated Secret Management Services Can Be Heavy

- Server operations and permission design add overhead
- The workflow often assumes constant network access
- The setup cost may be too high for small or mid-sized teams
- Secret changes do not fit naturally into Git-based PR review

### Existing Encryption Tools Often Do Not Match the Workflow

- GPG or PGP key distribution and rotation are cumbersome
- Updating a single `.env` value tends to create poor diffs
- It is hard to track who had access in the past after a member is removed

## What SecretEnv Provides

SecretEnv is meant to keep secrets out of plaintext handoffs while still letting teams use Git review and history. You do not need to understand the cryptographic design to use these day-to-day capabilities.

### 1. Manage `.env` Files in Git Without Leaving Them in Plaintext

```bash
# Initial setup
secretenv init --member-handle alice@example.com

# Import an existing .env file
secretenv import .env

# Update values by key
secretenv set DATABASE_URL "postgres://..."
secretenv set API_KEY "sk-..."
```

Each key in the `.env` file is stored as its own encrypted entry. Updating one value keeps the diff focused instead of rewriting everything, which makes Git diffs much easier to review.

### 2. Share Certificates and Binary Files the Same Way

```bash
secretenv encrypt certs/ca.pem
secretenv decrypt ca.pem.encrypted --out certs/ca.pem
```

SecretEnv is not limited to `.env` files. Certificates, config files, and arbitrary binaries flow through the same encryption and signature pipeline, and all of them are managed in the same workspace.

### 3. Run Commands Without Distributing Plaintext `.env`

```bash
secretenv run -- docker compose up
secretenv run -- npm start
secretenv run -- rails server

secretenv get DATABASE_URL
```

`run` decrypts the encrypted `.env` content on the fly, injects the values as environment variables, and starts the target process. Teams can move away from distributing plaintext `.env` files without changing how they normally launch their applications.

The child process inherits the parent process's environment by default; only environment variables whose names start with `SECRETENV_` are stripped before launch, so values you set in your shell (for example `PATH` or `RUST_LOG`) still reach the application.

Separate environments are managed with the `-n` option:

```bash
secretenv set -n staging DATABASE_URL "postgres://staging/..."
secretenv run -n prod -- ./deploy.sh
```

### 4. Member Onboarding Goes Through Git Review

```bash
# New member
secretenv join --member-handle bob@example.com
# -> creates a pending join request

# Existing member
secretenv rewrap
# -> approves the request and syncs access across encrypted files
```

A new member is added in a pending state first, then an existing member runs `rewrap` to approve and apply the change. Because membership changes appear as repository diffs, your team can review who joined and when through the normal PR flow.

### 5. Offboarding and Key Updates Are Mechanical

```bash
secretenv member remove alice@example.com
secretenv rewrap
```

After a member is removed, `rewrap` synchronizes recipient lists across encrypted files. Three flags refine the behavior depending on what you actually want to update:

- `secretenv rewrap --rotate-key` — rebuild the encryption key itself and re-encrypt the data
- `secretenv rewrap --clear-disclosure-history` — clear disclosure history after rotating or updating the values
- `secretenv rewrap --target <path>` — restrict the operation to specific encrypted artifacts when only some files need to be re-encrypted

### 6. Disclosure History Surfaces What Still Needs Rotation

SecretEnv records the history of members who were removed from access. For encrypted `.env` files, it also tracks entry-level disclosure state, which makes it easier to see which values still need to be rotated.

The important point is that removing a member does not recover secrets that were already disclosed in the past. SecretEnv does not hide that fact. Instead, it makes the residual risk visible so teams can make clean decisions about updating values and rotating keys.

### 7. CI/CD Works Without SSH Keys or an Agent

SecretEnv supports CI/CD environments through portable private key export:

```bash
# On a developer machine: export the CI member's key
secretenv key export --private --member-handle ci@example.com --out ci-key.txt
```

Register `SECRETENV_PRIVATE_KEY` and `SECRETENV_KEY_PASSWORD` as CI secret variables. The CI job can then use `secretenv run` and `secretenv get` without any SSH key, SSH agent, or local keystore. The CI member is still just another entry in the active member list, so its access can be revoked by the same `member remove` + `rewrap` flow.

### 8. Check That Member Keys Belong to the Right Person

```bash
# Verify active members against GitHub and approve them
secretenv member verify --approve

# Manage the local trust store
secretenv trust keys list
secretenv trust keys remove <kid>
secretenv trust recipients list
```

SecretEnv can confirm that an encrypted file was created by a particular key, but a person still needs to check whether that key belongs to the claimed member. `member verify --approve` cross-checks member public keys against GitHub accounts and saves approved key records in the local trust store. Use it as an extra check that makes key substitution easier to notice.

## Safety Signals and Assumptions

SecretEnv helps teams follow three practical rules: do not put plaintext secrets in Git, make secret changes reviewable, and stop sharing future secrets with removed members. It still assumes that workstations, private keys, PR review, and CI secrets are handled carefully.


| Concern                                                          | What SecretEnv does                                                                                              | What the team must handle                                              |
| ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `.env` content is read from the repository, a clone, or a backup | Stores secrets encrypted so only intended recipients can decrypt them                                            | Keep recipient membership accurate                                     |
| An encrypted file or its metadata is modified                    | Verifies signatures and structure before decryption, and stops on broken or unexpected content                   | Use PR review and protected branches to catch suspicious changes       |
| A new member key may not belong to the claimed person            | Uses `member verify --approve` to check GitHub account evidence and saves approved keys in the local trust store | Treat first approval as a real identity check                          |
| A former teammate keeps access to future secrets                 | Uses `member remove` and `rewrap` to remove that member from future sharing                                      | Rotate already disclosed values in the external services that use them |
| CI needs to run without SSH keys or an agent                     | Lets CI load an exported SecretEnv private key from secret variables                                             | Restrict use to trusted workflows, runners, and refs                   |


Core operations are offline-first. Encryption, decryption, verification, and `rewrap` work locally. GitHub integration is optional and mainly helps when you want an additional identity check between a public key and an account. The Security Design document covers the cryptographic details and threat model.

## Typical Adoption Flow

### What You Need

- An Ed25519 SSH key
- A Git repository
- A GitHub account
Optional. Useful if you want to verify the link between a public key and an account.
- Git practices such as PR review and protected branches for member changes
- For CI/CD use, an environment where CI secret variables are managed safely

### Installation

```bash
brew tap ebisawa/secretenv
brew install secretenv
```

### Add It to an Existing Project

Run the following commands inside a Git repository directory. SecretEnv auto-detects the workspace within a Git repository.

```bash
# Navigate to your Git repository
cd /path/to/your-repo

# 1. Create the workspace
secretenv init --member-handle alice@example.com

# 2. Import the existing .env file
secretenv import .env
```

After that, keep `.secretenv/` in Git and use `set`, `get`, `run`, `encrypt`, `decrypt`, and `rewrap` to manage secrets.

## Where SecretEnv Fits

SecretEnv is not a centralized access-control system. It is a lightweight and practical model for sharing team secrets safely in a way that fits naturally with Git.

What you can expect:

- reduce plaintext `.env` and certificate handoffs through chat
- review secret additions, updates, and membership changes as Git diffs
- sync future encrypted-file recipients after a member is removed
- keep past disclosure visible enough to decide which values need rotation

Good fit for teams that:

- already use Git and PR review as their main workflow
- want to share `.env` files or certificates safely in a small team
- do not want to depend on a SaaS or always-on secret platform
- need the same workflow to work offline, in local development, and in CI/CD

Not a good fit if you need to:

- enforce fine-grained access policies from a central system
- recover secrets after they were already disclosed
- prevent legitimate recipients from copying plaintext after decryption
- centrally control runtime secret injection across an entire cloud platform

## Learn More

- [User Guide](user_guide_en.md) — Installation, daily usage, and CI/CD setup
- [Security Design](security_design_en.md) — Threat model, cryptographic protocols, and trust architecture
