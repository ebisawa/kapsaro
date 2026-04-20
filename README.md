# secretenv

[日本語版 README はこちら](README_ja.md)

Want to stop sending `.env` files over Slack or DMs?  
But also do not want to rely on a dedicated server or an always-on secret management service?

`secretenv` is an offline-first CLI for sharing encrypted files for teams in that situation.  
It lets you manage `.env` files, certificates, key files, and other secrets in a Git repository without storing them in plaintext, while also fitting member changes and key updates into the normal Git review workflow.

Good fit for teams that want to:

- share `.env` files safely across a team
- manage certificates and config files with the same workflow
- use the same secret workflow in both local development and CI
- avoid depending on SaaS or dedicated infrastructure

The goal of this project is not only to avoid distributing secrets in plaintext.  
It is also to make it easier to reason about who a secret is shared with, whether it has been tampered with, and how membership changes or key updates should be applied, in a way that fits naturally with Git.

## Install

### Homebrew (macOS / Linux)

```bash
brew tap ebisawa/secretenv
brew install secretenv
```

### Shell script

```bash
curl -fsSL https://raw.githubusercontent.com/ebisawa/secretenv/main/install.sh | sh
```

### Build from source

```bash
git clone <secretenv-repo>
cd secretenv
cargo install --path .
```

## Getting Started

### 1. Initialize a workspace

```bash
cd /path/to/your-git-repo
secretenv init --member-handle alice@example.com
```

This creates a `.secretenv/` directory, generates your key pair, and registers you as the first member.
If the workspace already exists, `init` does nothing. Use `secretenv join` to submit a key to an existing workspace.

### 2. Add secrets

```bash
# Add individual entries
secretenv set DATABASE_URL "postgres://user:pass@localhost/mydb"
secretenv set API_KEY "sk-your-api-key"

# Or import an existing .env file
secretenv import .env
```

### 3. Commit to Git

```bash
git add .secretenv/
git commit -m "Initialize secretenv workspace"
```

### 4. Use your secrets

```bash
# Retrieve a single value
secretenv get DATABASE_URL

# Run a command with all secrets injected as environment variables
secretenv run -- ./my-app
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

If you want to learn about the local trust store:

- [Local Trust Store Update (English)](guides/trust_store_update_en.md)
- [Local Trust Store Update (Japanese)](guides/trust_store_update_ja.md)

## Status

This project is currently in alpha. Specification work and implementation are still evolving together.

## License

Apache-2.0. See [LICENSE](LICENSE).
