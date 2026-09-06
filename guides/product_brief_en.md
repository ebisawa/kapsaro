# Kapsaro: Share Encrypted `.env` Files Through Git

Kapsaro is an offline-first CLI for sharing encrypted secrets through Git. It handles `.env` key-value stores, certificates, private key files, configuration files, and other binary data. Teams review secret changes, membership, and key updates through the same pull-request workflow they use for code.

<a id="adoption-snapshot"></a>
## Suitable Uses and Limits

Kapsaro suits small and mid-sized teams that use Git and pull-request reviews, want to stop exchanging plaintext secrets, and need a common workflow for local development, offline work, and CI/CD. It requires no dedicated SaaS service or always-on server.

You can review secret additions, updates, and membership changes as Git diffs. Kapsaro uses HPKE, a standard public-key encryption scheme, to encrypt each file's master key separately for each recipient. The master key supplies the keys used to encrypt the data. When membership changes, you can synchronize recipients with the active team roster and use disclosure history to identify values that may need replacement.

Kapsaro cannot recall previously disclosed plaintext or prevent recipients from copying it. Organization-wide policies, fine-grained access controls, and centralized control of runtime secret injection require other systems.

<a id="common-problems"></a>
### Problems This Workflow Addresses

<a id="sharing-env-files-through-chat-or-manual-handoffs"></a>
<a id="using-envexample-with-manual-secret-handoffs"></a>
Plaintext handoffs leave secrets in chat histories and on machines, including those of former team members. Teams can lose track of the latest values and who changed them. An `.env.example` file documents expected keys, but developers still need to collect credentials during onboarding. Missed additions, renames, or updates can cause configuration differences that appear only in staging or CI.

<a id="dedicated-secret-management-services-can-be-heavy"></a>
A dedicated service may require server maintenance, permission design, and continuous connectivity. Its setup and operating costs can be disproportionate for a small team, and its change process may sit outside Git reviews.

<a id="encryption-alone-leaves-operational-questions-unanswered"></a>
Encryption also leaves operational work: reviewing key and recipient changes, recording approvals, identifying values that departing members could access, and managing CI credentials. Kapsaro combines these tasks with repository changes; teams still need review practices and credential revocation procedures.

<a id="comparing-alternatives"></a>
### Comparing Approaches

| Requirement | Approach to Consider |
| --- | --- |
| `.env` encryption and runtime injection | Kapsaro or a tool dedicated to this workflow |
| File encryption with existing or external key management | A file encryption tool that integrates with the required key management system |
| Central policy enforcement, SSO, SCIM, or fine-grained ACLs | A centralized secret management platform |
| Secret and membership changes reviewed through Git and pull requests | Kapsaro |
| `.env` files, certificates, CI read access, key updates, and disclosure history for a small or mid-sized team | Kapsaro |

<a id="typical-adoption-flow"></a>
## Getting Started

### Prerequisites

- An Ed25519 SSH key
- A Git repository
- A GitHub account, if you want to verify the association between a public key and an account
- Git review practices, such as pull-request reviews and protected branches, for membership changes
- Securely managed CI secret variables, if you use CI/CD

### Adding Kapsaro to an Existing Project

The following Homebrew example installs Kapsaro and creates a workspace. Run the initialization commands from your repository root. Kapsaro detects an existing workspace when you run commands inside the repository. Other installation methods are in the [User Guide](user_guide_en.md).

```bash
# Install Kapsaro
brew tap ebisawa/kapsaro
brew install kapsaro

# Create the workspace
kapsaro init --member-handle alice@example.com

# Import an existing .env file
kapsaro import .env

# Check decryption without printing secrets
kapsaro run -- true
```

Commit `.kapsaro/` to Git and keep plaintext source files out of the repository. Use `set`, `get`, `run`, `encrypt`, `decrypt`, and `rewrap` for subsequent changes and reads.

<a id="what-kapsaro-provides"></a>
## Daily Operations

<a id="1-manage-env-files-in-git-without-plaintext-exposure"></a>
### Update Values by Key

```bash
kapsaro set DATABASE_URL "postgres://..."
kapsaro set API_KEY "sk-..."
```

These values are placeholders. For real secrets, use the [secret input procedure](user_guide_en.md#secret-input) to avoid leaving values in shell history or command arguments.

Each `.env` key has an independently encrypted entry, so Git diffs show which entries changed. The digital signature covers the entire document: editing different keys still changes shared metadata such as the signature. Resolve merge conflicts by [reapplying changes to a valid document](user_guide_en.md#git-conflict-resolution).

<a id="2-share-certificates-and-binary-files-with-the-same-workflow"></a>
### Encrypt and Decrypt Files

```bash
kapsaro encrypt certs/ca.pem
kapsaro decrypt ca.pem.encrypted --out certs/ca.pem
```

Certificates, configuration files, and other binary files use the same workspace and the same underlying encryption and signature mechanisms as key-value stores.

<a id="3-run-commands-without-distributing-plaintext-env-files"></a>
### Run Applications and Read Values

```bash
kapsaro run -- docker compose up
kapsaro run -- npm start
kapsaro run -- rails server

kapsaro get DATABASE_URL
kapsaro get API_KEY
```

`kapsaro run` decrypts the entries, passes them to the child process as environment variables, and starts the requested command. The child inherits the parent environment, including variables such as `PATH` and `RUST_LOG`; Kapsaro removes inherited variables whose names start with `KAPSARO_`. The child process can read and disclose the decrypted values. `kapsaro get` prints a value, so use it only where terminal output is appropriate.

Use `-n` to select a named store:

```bash
kapsaro set -n staging DATABASE_URL "postgres://staging/..."
kapsaro run -n prod -- ./deploy.sh
```

Names such as `dev`, `staging`, and `prod` organize values within a workspace. Recipients are managed per workspace. [Use separate workspaces](user_guide_en.md#workspace-sharing) when environments need different recipient groups.

## Members and Public Keys

<a id="4-onboard-members-through-standard-git-reviews"></a>
### Add a Member

```bash
# New member: create a pending join request
kapsaro join --member-handle bob@example.com

# Existing member: review the request and update recipients
kapsaro rewrap
```

The new member starts in the pending state, called `incoming`. Share the request through Git so an existing member can review it. That member runs `rewrap` to approve the request and update encrypted files under the workspace's `secrets/` directory (`.kapsaro/secrets/` in a standard layout). Membership changes appear as repository diffs for pull-request review.

Complete onboarding by committing and sharing both member records and updated encrypted files, then confirming decryption on the new member's machine. See [membership completion checks](user_guide_en.md#membership-completion), including files stored outside the default directory.

<a id="8-verify-member-key-authenticity"></a>
### Verify and Approve Public Keys

```bash
# Verify active member keys against GitHub and approve the keys locally
kapsaro member verify --approve

# Inspect and manage local trust records
kapsaro trust keys list
kapsaro trust keys remove <kid>
kapsaro trust recipients list
```

A valid artifact signature establishes that the signing key signed the document. Associating that key with the claimed person requires separate verification. `member verify --approve` checks member public keys with GitHub and, after confirmation, records approved keys in the local trust store. This checks the key's association with the claimed GitHub account; the team must establish whom that account represents. The trust store keeps approved keys and recipient sets for later comparisons, helping detect unexpected changes. `<kid>` is a key identifier.

Public-key approval is separate from admitting an incoming member. `rewrap` handles admission and recipient synchronization; `member verify --approve` records local key approval.

<a id="5-streamlined-offboarding-and-key-updates"></a>
### Remove Members and Update Keys

```bash
kapsaro member remove old-member@example.com
kapsaro rewrap
```

`rewrap` synchronizes encrypted-file recipients with current membership. By default, it scans the workspace's `secrets/` directory. Use `--target` for encrypted files elsewhere.

- `kapsaro rewrap --rotate-key` generates a new master key and re-encrypts the data. Member public and private keys remain unchanged.
- `kapsaro rewrap --clear-disclosure-history` clears recorded disclosures after you replace affected secret values. Clearing the record does not revoke credentials or erase past exposure.
- `kapsaro rewrap --target <path>` selects the files to process.

For member-key replacement, follow the [key update and verification procedure](user_guide_en.md#new-key-verification). Synchronizing recipients and rotating a file's master key serve different purposes from replacing a member's key pair.

<a id="6-disclosure-history-highlights-values-requiring-rotation"></a>
### Use Disclosure History During Offboarding

Kapsaro records removed recipients and, for encrypted key-value stores, which entries may have been disclosed to them. This identifies values to review for replacement; it does not establish whether anyone actually read them.

Removing a recipient affects the updated encrypted files. Previously decrypted values and older encrypted copies may remain accessible. Complete offboarding by updating and sharing the encrypted files, checking access from the shared commit, and revoking or replacing affected tokens and passwords at their issuing services. See the [member management procedure](user_guide_en.md#6-member-management).

<a id="7-cicd-integration-without-ssh-keys-or-agents"></a>
## CI/CD

Kapsaro can export a member's private key in a portable, password-protected form:

```bash
# On a developer machine: export the CI member's private key
kapsaro key export --private --member-handle ci@example.com --out ci-key.txt
```

Register the exported key as `KAPSARO_PRIVATE_KEY` and its password as `KAPSARO_KEY_PASSWORD` in the CI secret store. The pipeline can then use `run` or `get` without an SSH key, SSH agent, or local keystore. Set up the CI member and verify that it can decrypt the shared files before using it in a job.

CI bots follow the same membership rules as people. Removing a CI member and running `rewrap` updates recipients; retiring or compromised CI credentials also require revoking or replacing the secrets that the bot could access.

Access remains scoped to the workspace. Put only required secrets in a dedicated CI workspace, and expose its credentials only to trusted build steps that need them. See [CI setup](user_guide_en.md#ci-setup) for version-pinned installation, build attestation verification, trust prerequisites, and decryption checks.

<a id="documentation"></a>
## Related Documents

- [User Guide](user_guide_en.md) — Installation, daily operations, and CI/CD setup
- [Security Design](security_design_en.md) — Threat model, cryptographic protocols, and trust decisions
