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

## Design Starting Point

Before describing what SecretEnv does, it helps to state what it does not assume. SecretEnv treats the Git repository as a tamperable distribution medium. Anyone with write access — a teammate, a misconfigured CI job, an unauthorized push path — could in principle rewrite files under `.secretenv/`. The design therefore never makes the repository itself the cryptographic anchor of trust.

The trust anchor instead lives on each user's device: the local private key, the local keystore, the local trust store, and the SSH key. Everything in the repository — the active member list, incoming join requests, and encrypted files — is treated as input that must be validated before it is trusted. The four design axes below all follow from this single starting point.

## The Four Design Axes

To make "do not cryptographically trust the distribution medium" workable in practice, SecretEnv weaves four axes into the design. They are not independent features. Each axis covers a gap the others cannot, and only the combination realizes the starting point above.

### Axis 1: Confidentiality and Integrity Carried by the Encrypted Artifacts

If the medium is not trusted, the artifacts themselves must carry confidentiality and integrity. SecretEnv distributes the content key per recipient via HPKE wrap, encrypts the body with XChaCha20-Poly1305 (AEAD), and binds ciphertext together with metadata under an Ed25519 signature. Standardized constructions are chosen so that each artifact can be evaluated on its own, without depending on the medium that delivered it.

### Axis 2: Self-Contained Verification

Verification must not depend on calling out to an external key server or fetching a separate file at verify time — that path would itself become a new trust dependency, and would also break offline use. SecretEnv embeds the signer's public-key document into every signed artifact, and that public-key document is in turn protected by a self-signature combined with SSH attestation. The authenticity of the verification key is closed inside the artifact.

### Axis 3: Role-Separated Trust Policy

"Whose key is this, and may I accept it now?" is not a single question. The cryptographic correctness of a key, the fact that it is currently a member key, and the fact that the user has previously confirmed it are three separate judgments. SecretEnv keeps them as three separate roles:

- the embedded signer public key — input to cryptographic verification
- the active member list — authorization basis for the current member and recipient set
- the approved-keys cache (also referred to as the local trust store) — record of the user's TOFU approvals

By layering them rather than collapsing them, mechanical cryptographic verification, current-trust-state judgment, and identity assurance can each be operated without conflating with the others.

### Axis 4: Context Binding

Even when the primitives are individually correct, swapping artifacts across contexts can defeat them. A wrap produced for another file, a signature from an old key generation, or a ciphertext fragment intended for another entry could otherwise be slipped into the current context and still pass cryptographic verification. SecretEnv cryptographically binds each artifact to the context it belongs to — file identifier, key generation, entry identifier, protocol identifier — so that swaps and reuse are detected as context mismatches.

## What SecretEnv Provides

The four axes above are the security backbone. The following sections describe how that backbone shows up in day-to-day usage.

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

Each key in the `.env` file is stored as its own encrypted entry. Updating one value keeps the diff focused instead of rewriting everything, which makes Git diffs much easier to review. Each entry is also bound to the file and entry identifier, so an entry encrypted for one place cannot be silently reused elsewhere.

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

A new member is added in a pending state first, then an existing member runs `rewrap` to approve and apply the change. Because membership changes appear as repository diffs, your team can review who joined and when through the normal PR flow. The active member list, not the embedded signer public key, is what authorizes recipients, which is why this step is reviewable rather than purely cryptographic.

### 5. Offboarding and Key Updates Are Mechanical

```bash
secretenv member remove alice@example.com
secretenv rewrap
```

After a member is removed, `rewrap` synchronizes recipient lists across encrypted files. Three flags refine the behavior depending on what you actually want to update:

- `secretenv rewrap --rotate-key` — rebuild the encryption key itself and re-encrypt the data; the new key generation gets a fresh context binding, so old wraps cannot survive the rotation
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

### 8. Key Identity Verification Reduces Supply Chain Risk

```bash
# Verify active members against GitHub and approve them
secretenv member verify --approve

# Manage the local trust store
secretenv trust list
secretenv trust remove <kid>
```

Cryptographic verification establishes that an artifact was signed by a particular key, but not that the key actually belongs to the person it claims to. `member verify --approve` cross-checks member public keys against GitHub accounts and saves the result in the local trust store (the approved-keys cache). This adds a layer of protection against public key substitution without requiring a PKI.

## Why It Is Safe

The table below lists representative risks of sharing secrets through Git and how SecretEnv addresses each of them. The Security Design document covers the assumptions and residual risks behind each row in more detail.

| Representative risk | How SecretEnv addresses it |
| --- | --- |
| `.env` content is read from the repository, a clone, or a backup | HPKE wrap delivers the content key only to current recipients; the body is encrypted with XChaCha20-Poly1305 AEAD |
| An encrypted file or its metadata is silently modified | Every artifact carries an Ed25519 signature and verification runs before decryption |
| Verification depends on an external key server that could go down or be tampered with | Each signed artifact embeds the signer's public-key document, so verification is closed inside the artifact and works offline |
| A removed teammate keeps the ability to decrypt new secrets | The active member list is the authorization basis for `rewrap`, so leaving the team revokes future access |
| An attacker swaps fragments between encrypted files to slip a forgery past verification | Each artifact is bound to its file, key generation, entry, and protocol, so cross-context substitution fails verification |
| An exported CI private key leaks from the CI provider | The exported key is protected by a password (`SECRETENV_KEY_PASSWORD`) and revoked the same way as any other member |

Core operations are offline-first. Encryption, decryption, signature verification, and `rewrap` work locally. GitHub integration is optional and mainly helps when you want an additional identity check between a public key and an account.

## Typical Adoption Flow

### What You Need

- An Ed25519 SSH key
- A Git repository
- A GitHub account
  Optional. Useful if you want to verify the link between a public key and an account.

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
- [Local Trust Store Update](trust_store_update_en.md) — Day-to-day trust store maintenance and migration

---

SecretEnv stops the distribution of plaintext `.env` files through Slack and DMs. Encrypt them, share them through Git, and let your team's existing review workflow be the security gate.
