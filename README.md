# Kapsaro

[日本語版 README はこちら](README_ja.md)

> [!NOTE]
> This project has been renamed from SecretEnv to Kapsaro.

`kapsaro` is an offline-first CLI for development teams that want to share API tokens, database passwords, certificates, `.env` values, and other development secrets without passing them around in plaintext.

It fits teams that already use Git and pull-request review as their daily workflow. Secrets, member changes, removals, and key rotation are represented as encrypted repository changes, so the team can review secret-sharing decisions through the same process they already use for code.

No dedicated cloud service, SaaS secret platform, or always-on server is required. Encryption, decryption, verification, and recipient updates work locally and offline, while Git remains the shared transport and review layer.

This project is currently in alpha. Feedback from trials, design reviews, and realistic team workflows is welcome before production adoption.

## What You Can Do First

Kapsaro lets you move these workflows into Git review:

- encrypt an existing `.env` file and share it without committing plaintext
- decrypt encrypted secrets just in time to run normal development commands
- sync future recipients after a member is removed

```bash
# Encrypt an existing .env file into Git-managed storage
kapsaro init --member-handle alice@example.com
kapsaro import .env

# Run the app without distributing a plaintext .env file
kapsaro run -- npm start

# Remove a member from future sharing
kapsaro member remove old-member@example.com
kapsaro rewrap
```

## What Encryption Alone Does Not Solve

Even if secret files are encrypted, teams still need to decide:

- when a new member should receive each secret
- whether a removed member has been excluded from future sharing
- whether values a removed member could previously read need to be updated

Kapsaro records removed-member history and shows entry-level signals that help teams decide which `.env` values may need updates. Secret updates and membership changes are stored as files, so teams can review them in normal pull requests. For the broader positioning, see the [Product Brief](guides/product_brief_en.md).

## Security Highlights

`kapsaro` encrypts values that should stay private, such as access tokens, API keys, and certificates, so each member uses their own key material to decrypt. Teams do not need to distribute one shared encryption key; only members included as recipients can read the encrypted content.

The design is built around five ideas:

- encrypt secrets before they are stored in the repository, so a repository shared by many members can still carry sensitive values safely
- use public-key encryption to share the information needed for decryption separately with each recipient
- use proven, standards-based cryptographic schemes including HPKE, Ed25519 signatures, XChaCha20-Poly1305, and HKDF-SHA256
- require no dedicated server or SaaS; encryption, decryption, verification, and recipient updates are designed to work offline, even without network access
- verify signatures and recipient information before decrypting or updating encrypted artifacts

## Install

### Homebrew (macOS / Linux)

```bash
brew tap ebisawa/kapsaro
brew install kapsaro
```

### Shell script

```bash
curl -fsSL https://raw.githubusercontent.com/ebisawa/kapsaro/main/install.sh | sh
```

### Build from source

```bash
git clone <kapsaro-repo>
cd kapsaro
cargo install --path .
```

## Getting Started

### 1. Initialize a workspace

```bash
cd /path/to/your-git-repo
kapsaro init --member-handle alice@example.com
```

This creates a `.kapsaro/` directory, generates your key pair, and registers you as the first member.
If the workspace already exists, `init` does nothing. Use `kapsaro join` to submit a key to an existing workspace.

### 2. Add secrets

```bash
# Add individual entries
kapsaro set DATABASE_URL "postgres://user:pass@localhost/mydb"
kapsaro set API_KEY "sk-your-api-key"

# Or import an existing .env file
kapsaro import .env
```

### 3. Commit to Git

```bash
git add .kapsaro/
git commit -m "Initialize kapsaro workspace"
```

### 4. Use your secrets

```bash
# Retrieve a single value
kapsaro get DATABASE_URL

# Run a command with all secrets injected as environment variables
kapsaro run -- ./my-app
```

Check workspace health before onboarding, CI setup, or release work:

```bash
kapsaro doctor
```

For detailed setup and operational guidance, see the [User Guide](guides/user_guide_en.md).

## Read More

If you want the high-level overview first:

- [Product Brief (English)](guides/product_brief_en.md)
- [Product Brief (Japanese)](guides/product_brief_ja.md)

If you want setup and operational guidance:

- [User Guide (English)](guides/user_guide_en.md)
- [User Guide (Japanese)](guides/user_guide_ja.md)

If you want the security model and design details:

- [Security Design (English)](guides/security_design_en.md)
- [Security Design (Japanese)](guides/security_design_ja.md)

## Status

This project is currently in alpha. Specification work and implementation are still evolving together.

## License

Apache-2.0. See [LICENSE](LICENSE).
