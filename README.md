# Kapsaro

[日本語版 README はこちら](README_ja.md)

> [!NOTE]
> This project has been renamed from SecretEnv to Kapsaro.

`kapsaro` is an offline-first CLI tool for development teams looking to share API tokens, database credentials, certificates, `.env` values, and other sensitive development secrets without passing them around in plaintext.

It is designed for teams that already rely on Git and pull-request reviews in their daily workflow. Secrets, membership changes (additions and removals), and key rotations are represented as encrypted changes in the repository, allowing teams to review secret-sharing decisions through the exact same workflow they already use for code.

No dedicated cloud service, SaaS secret manager, or always-on server is required. Encryption, decryption, verification, and recipient updates all work locally and offline, with Git serving as the shared transport and review layer.

This project is currently in beta. Feedback from trials, design reviews, and real-world team workflows is welcome ahead of production adoption.

## What You Can Do First

Kapsaro lets you bring these workflows directly into your Git review process:

- Encrypt an existing `.env` file and share it without committing plaintext
- Decrypt encrypted secrets just-in-time to run standard development commands
- Update future recipients whenever a team member is removed

```bash
# Encrypt an existing .env file into Git-managed storage
kapsaro init --member-handle alice@example.com
kapsaro import .env

# Run your app without distributing a plaintext .env file
kapsaro run -- npm start

# Remove a member from future secret sharing
kapsaro member remove old-member@example.com
kapsaro rewrap
```

By default, `rewrap` scans the workspace's `secrets/` directory; use `--target` for encrypted files stored elsewhere. To complete a membership change, review and commit both the member records and the updated encrypted files, then verify decryption from the shared commit. For details, see [membership completion checks](guides/user_guide_en.md#membership-completion).

## What Encryption Alone Does Not Solve

Even when secret files are encrypted, teams still face operational questions:

- Which secrets should a new member receive, and when?
- Has a removed member been excluded from future secret updates?
- Do any values previously accessible to a removed member need to be rotated?

Kapsaro maintains a history of removed members and surfaces entry-level indicators to help teams decide which `.env` values may need rotation. Because secret updates and membership changes are stored as regular files, teams can review every change in standard pull requests. For a broader overview of this approach, see the [Product Brief](guides/product_brief_en.md).

## Security Highlights

`kapsaro` protects sensitive values—such as access tokens, API keys, and certificates—by ensuring each member decrypts using their own individual key material. Teams never need to distribute a shared master key or passphrase; only members explicitly designated as recipients can decrypt and read the content.

The architecture is built around five core principles:

- **Pre-commit encryption**: Encrypt secrets before storing them in the repository, making it safe to commit sensitive values to shared Git repositories.
- **Recipient-specific public-key encryption**: Use public-key cryptography to share decryption keys individually with each authorized recipient rather than using a single shared password.
- **Proven cryptographic standards**: Rely on modern, standards-based cryptographic schemes, including HPKE (RFC 9180), Ed25519 signatures, XChaCha20-Poly1305, and HKDF-SHA256.
- **Offline-first design**: Require no dedicated server or SaaS platform; encryption, decryption, verification, and recipient updates are all designed to work completely offline.
- **Strict verification**: Verify cryptographic signatures and recipient information before decrypting or updating any encrypted artifact.

## Installation

### Homebrew (macOS / Linux)

```bash
brew tap ebisawa/kapsaro
brew install kapsaro
```

### Shell Script

```bash
curl -fsSL https://raw.githubusercontent.com/ebisawa/kapsaro/main/install.sh | sh
```

The installer verifies each release archive's build provenance with GitHub Artifact Attestations using the GitHub CLI (`gh`), and verification is required by default. If `gh` is not installed, or to skip verification deliberately, set `KAPSARO_INSECURE=1` to install without it.

### Build from Source

```bash
git clone https://github.com/ebisawa/kapsaro.git
cd kapsaro
cargo install --path .
```

## Getting Started

### 1. Initialize a workspace

```bash
cd /path/to/your-git-repo
kapsaro init --member-handle alice@example.com
```

This creates the `.kapsaro/` directory, generates your key pair, and registers you as the initial member.
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

Check workspace health before onboarding members, configuring CI, or preparing releases:

```bash
kapsaro doctor
```

For detailed setup and operational guidance, see the [User Guide](guides/user_guide_en.md).

For team operations, see [resolving Git conflicts](guides/user_guide_en.md#git-conflict-resolution) and [CI setup with a pinned, verified release](guides/user_guide_en.md#ci-setup). Named stores organize values within a workspace; use separate workspaces for different recipient groups, including CI.

## Documentation

If you want a high-level overview first:

- [Product Brief (English)](guides/product_brief_en.md)
- [Product Brief (Japanese)](guides/product_brief_ja.md)

If you want setup and operational guidance:

- [User Guide (English)](guides/user_guide_en.md)
- [User Guide (Japanese)](guides/user_guide_ja.md)
- [Windows / WSL2 Supplemental Guide (English)](guides/wsl_user_guide_en.md)
- [Windows / WSL2 Supplemental Guide (Japanese)](guides/wsl_user_guide_ja.md)

If you want the security model and design details:

- [Security Design (English)](guides/security_design_en.md)
- [Security Design (Japanese)](guides/security_design_ja.md)

## Status

This project is currently in beta. During the beta phase, external specifications (such as file formats) remain frozen unless a critical issue requires changes. Ongoing work toward the stable release focuses on bug fixes and UI refinements.

## License

Apache-2.0. See [LICENSE](LICENSE).
