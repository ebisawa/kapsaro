# SecretEnv: Share Encrypted `.env` Files Through Git

How does your team share `.env` files, certificates, and private key files today?

SecretEnv is an offline-first CLI for sharing secrets through a Git repository without storing them in plaintext. It works for both `.env`-style key-value files and arbitrary files such as certificates or config files, and it lets you manage membership and key updates through the same Git review flow your team already uses.

## Common Problems

### Sending `.env` Files Through Slack or DMs

- Plaintext secrets remain in message history and on local machines
- It becomes unclear who has the latest version
- Former team members may continue holding old values
- It is hard to track who changed what and when

### `.env.example` Plus Manual Secret Distribution

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

SecretEnv organizes secret sharing around both encryption and Git-based team workflows.

### 1. You Can Manage `.env` Files in Git Without Leaving Them in Plaintext

```bash
# Initial setup
secretenv init --member-handle alice@example.com

# Import an existing .env file
secretenv import .env

# Update values by key
secretenv set DATABASE_URL "postgres://..."
secretenv set API_KEY "sk-..."
```

Each key in the `.env` file is stored as its own encrypted entry. When you update one value, the diff stays focused instead of rewriting everything, which makes Git diffs much easier to review.

### 2. You Can Share Certificates and Binary Files the Same Way

```bash
secretenv encrypt certs/ca.pem
secretenv decrypt ca.pem.encrypted --out certs/ca.pem
```

This is not limited to `.env` files. Certificates, config files, and arbitrary binaries can be managed in the same workspace.

### 3. It Does Not Disrupt Existing Development Workflows

```bash
secretenv run -- docker compose up
secretenv run -- npm start
secretenv run -- rails server

secretenv get DATABASE_URL
```

`run` decrypts the encrypted `.env` content on the fly, injects it as environment variables, and starts the target process. This lets teams move away from distributing plaintext `.env` files without changing how they normally run commands.

Separate environments are managed with the `-n` option:

```bash
secretenv set -n staging DATABASE_URL "postgres://staging/..."
secretenv run -n prod -- ./deploy.sh
```

### 4. Member Onboarding and Approval Fit into Git Review

```bash
# New member
secretenv join --member-handle bob@example.com
# -> creates a pending join request

# Existing member
secretenv rewrap
# -> approves the request and syncs access across encrypted files
```

New members are added in a pending state first. An existing member then runs `rewrap` to approve and apply the change. Because membership changes appear as repository diffs, your team can review who joined and when through the normal PR flow.

### 5. Offboarding and Key Updates Can Be Done Mechanically

```bash
secretenv member remove alice@example.com
secretenv rewrap
```

After a member is removed, `rewrap` synchronizes access across encrypted files. When needed, you can also choose between:

- `secretenv rewrap --rotate-key`
  Rebuild the encryption key itself and re-encrypt the data
- `secretenv rewrap --clear-disclosure-history`
  Clear disclosure history after rotating or updating the values

### 6. Disclosure History Helps You See What Still Needs Rotation

SecretEnv records the history of members who were removed from access. For encrypted `.env` files, it also tracks entry-level disclosure state, which makes it easier to see which values still need to be rotated.

The important point is that **removing a member does not recover secrets that were already disclosed in the past**. SecretEnv does not hide that fact. Instead, it makes the risk visible so teams can make clean decisions about updating values and rotating keys.

### 7. CI/CD Works Without SSH Keys or an Agent

SecretEnv supports CI/CD environments through portable private key export:

```bash
# On a developer machine: export the CI member's key
secretenv key export --private --member-handle ci@example.com --out ci-key.txt
```

Register `SECRETENV_PRIVATE_KEY` and `SECRETENV_KEY_PASSWORD` as CI secret variables. The CI job can then use `secretenv run` and `secretenv get` without any SSH key, SSH agent, or local keystore.

### 8. Key Identity Verification Reduces Supply Chain Risk

```bash
# Verify active members against GitHub and approve them
secretenv member verify --approve

# Manage the local trust store
secretenv trust list
secretenv trust remove <kid>
```

SecretEnv separates current membership from approval history. `member verify --approve` cross-checks member public keys against GitHub accounts and saves the result in a local trust store. This adds a layer of protection against public key substitution without requiring a PKI.

## Why It Is Safe

SecretEnv focuses on the following properties.

| What is protected | How | Result |
| --- | --- | --- |
| Confidentiality | HPKE + AEAD | Only the current authorized members can decrypt |
| Tamper detection | Ed25519 signatures | Detects modification of encrypted files and metadata |
| Context binding | The design ties encrypted data to the file and key names | Prevents swapping content across different secrets or entries |
| Key rotation consistency | The design binds encrypted data to specific key statements | Prevents mix-ups during key rotation and key replacement |
| Trust decisions | `members/active` as the authorization source, local trust store as a TOFU approval cache | Separates current membership from approval history |
| Stronger key identity checks | SSH-key binding plus GitHub verification | Reduces the risk of public key substitution |

Core operations are offline-first. Encryption, decryption, signature verification, and `rewrap` work locally. GitHub integration is optional and mainly helps when you want an additional identity check between a public key and an account.

## Typical Adoption Flow

### What You Need

- An Ed25519 SSH key
- A Git repository
- A GitHub account
  Optional. Useful if you want to verify the link between a public key and an account

### Installation

```bash
brew tap ebisawa/secretenv
brew install secretenv
```

### Add It to an Existing Project

Run the following commands inside a Git repository directory. secretenv auto-detects the workspace within a Git repository.

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

SecretEnv is not a centralized access-control system like a dedicated secret management service. It is a lightweight and practical model for sharing team secrets safely in a way that fits naturally with Git.

Good fit for teams that:

- already use Git and PR review as their main workflow
- want to share `.env` files or certificates safely in a small team
- do not want to depend on a SaaS or always-on secret platform
- need the same workflow to work offline, in local development, and in CI/CD

Not a good fit if you need to:

- enforce fine-grained access policies from a central system
- recover secrets after they were already disclosed
- centrally control runtime secret injection across an entire cloud platform

## Learn More

- [User Guide](user_guide_en.md) — Installation, daily usage, and CI/CD setup
- [Security Design](security_design_en.md) — Threat model, cryptographic protocols, and trust architecture

---

**SecretEnv** — Stop sending `.env` files through Slack. Encrypt them, share them through Git, and let your team's existing review workflow handle the rest.
