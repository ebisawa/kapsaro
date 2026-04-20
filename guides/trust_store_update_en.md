# SecretEnv: Introducing the Local Trust Store

---

## 1. Overview

This update adds a **local trust store** to each user's local environment.

In short, **it lets you save a local record that you have previously verified a given key**.

### What changes

- When reading or writing secrets, a check is performed to see whether the signer's / recipient's key (`kid`) is **in your list of verified keys**
- When an unverified `kid` is encountered, an interactive approval prompt is presented
- Once approved, the `kid` is recorded in `known_keys` and subsequent encounters require no re-confirmation
- Approval history can be managed via the `trust list` / `trust remove` / `trust purge` commands

### What stays the same

- The signature verification mechanism (embedded `signer_pub`) is unchanged
- Current member determination is still governed by `members/active` in the repository
- No team-wide trust policy or permission management is introduced

In other words, the local trust store is not a replacement for member management — it is a **per-user approval cache**.

---

## 2. Background

In previous versions, every time you ran `decrypt`, `get`, `run`, `set`, or similar commands, you had to judge from scratch whether the signer or recipient was legitimate. In practice, re-verifying the same team members' keys every time is an excessive burden.

When the burden is too high, users tend to gloss over verification, and a design intended to "verify" becomes an operation where "nothing is checked".

The local trust store is a mechanism where **the user performs the initial verification, and the result is remembered so that subsequent verifications can be skipped**. It does not eliminate verification — it eliminates repeating the same verification.

---

## 3. Three Verification Layers

To understand the local trust store, it is important not to conflate the following three roles.

| Layer | What it examines | Role |
|-------|-----------------|------|
| `signer_pub` | Signer key embedded in the cryptographic artifact | Cryptographic signature verification |
| `members/active` | Member list in the repository | Current member / recipient determination |
| `known_keys` | User-local trust store | Record of "whether I have verified this" |

**`signer_pub`** verifies which key signed the artifact in a self-contained manner. It confirms signature correctness without depending on the workspace.

**`members/active`** is the criterion for determining "whether to accept this signer / recipient as part of the current team". Since it resides in the repository, it is protected by Git access controls and PR reviews.

**`known_keys`** is a cache that only remembers "whether I have previously verified this `kid`". It is maintained per-user and globally, without distinguishing between workspaces or roles (signer / recipient).

### Why `known_keys` is shared across workspaces

A `kid` is an identifier for a key statement. Re-verifying the same key every time it appears in a different clone or workspace is inefficient. Per-workspace state is held on the repo side (`members/active`), while the user's verification history is held on the local side — a clean separation of concerns.

---

## 4. Impact on Daily Operations

### 4.1 Read path (decrypt / get / run)

With this update, reading a cryptographic artifact requires all of the following to be satisfied:

1. The signature is cryptographically valid (verified with `signer_pub`)
2. The signer's `(member_id, kid)` exists in `members/active`
3. The signer's `kid` is in `known_keys`, **or** is approved interactively in the current session

In other words, **a valid signature alone is not sufficient — you must also have previously verified the signer**.

Your own (self) key is already trusted via the local keystore, so the `known_keys` check is skipped.

### 4.2 Write path (encrypt / set / unset / import / rewrap)

Recipients for write operations are derived from `members/active`. With this update, each derived recipient's `kid` must also be in `known_keys` or be approved interactively.

In other words, **approval checks apply not only to reading but also to "who you encrypt for"**.

### 4.3 Interactive approval prompt

When an unverified `kid` is encountered, information like the following is displayed:

```
Trust review for signer:
  member_id: bob@example.com
  kid: 7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD
  attestation fingerprint: SHA256:xxxx...
  GitHub account id: 12345678 (bob-gh)
  Warning: First-contact trust is TOFU. Verify kid / GitHub id / fingerprint out of band.

Approve this key and add it to local trust store? [y/N]
```

It is recommended to verify the `kid`, GitHub account, and SSH attestation fingerprint with the person **through a separate channel** such as Slack or a video call.

---

## 5. First Steps After Migration

### 5.1 Approve existing members' keys

After updating, first verify and approve the keys of active members.

```bash
# Verify and approve all active members at once
secretenv member verify --approve

# Approve specific members only
secretenv member verify --approve alice@example.com bob@example.com
```

This command performs the following for each member:

1. Offline verification of the PublicKey (schema, self-signature, attestation)
2. Online verification via GitHub API if a GitHub binding exists (SSH key matching)
3. Display of verification results and decision materials (`kid`, attestation fingerprint, GitHub account id/login)
4. Interactive approval confirmation

Once approved, the key is recorded in `known_keys`, and no re-confirmation is needed for the same `kid` in subsequent read/write operations.
Keys that already exist in `known_keys` are not shown in this command's results.

Example output:

```
✓ approved alice@example.com
✓ approved bob@example.com

Approved 2/2 members
```

### 5.2 Check the trust store state

```bash
# Display the list of approved keys
secretenv trust list
```

Example output:

```
alice@example.com  3KX9V2D7... (approved: 2026-04-01T10:00:00Z, via: manual-review)
bob@example.com    7M2Q9D4R... (approved: 2026-04-01T10:05:00Z, via: manual-review)

2 known key(s)
```

---

## 6. Operational Scenarios

### 6.1 Setting up a new workspace

When you create a workspace with `secretenv init`, your PublicKey is placed in `members/active`. The trust store is not created automatically. Since your own key is trusted without `known_keys`, **the first member can start operating without a trust store**.

The trust store is automatically created when you first approve another member's key.

### 6.2 Onboarding a new member

```bash
# 1. New member joins (placed in incoming)
#    Run on the new member's side
secretenv join --member-handle newuser@example.com

# 2. After reviewing and merging the new member's PR,
#    verify and approve if not yet done
secretenv member verify --approve newuser@example.com

# 3. Rewrap to promote incoming → active and update encrypted files
secretenv rewrap
```

`rewrap` processes in the following order:

1. Verification of incoming candidates (offline verify required)
2. `kid` collision check (rejected if `known_keys` contains the same `kid` for a different member)
3. Interactive approval for any unverified `kid` (fails in non-interactive execution)
4. Promotion of candidates to active
5. Derivation of recipients from the post-promotion member set, re-encrypting all encrypted files

**Recommendation:** Complete approvals with `member verify --approve` before running `rewrap` to reduce interactive prompts during the rewrap process.

### 6.3 Everyday secret read/write

In a team where all keys have been approved, the experience is almost identical to previous versions.

```bash
secretenv get DB_PASSWORD       # No extra confirmation if approved
secretenv set API_KEY=xxx       # No extra confirmation if all recipients are approved
secretenv run -- ./deploy.sh    # No extra confirmation if approved
```

Interactive prompts are shown only when an unapproved `kid` is present.

### 6.4 Key rotation

When a member starts using a new key (new `kid`):

```bash
# Verify and approve the new kid
secretenv member verify --approve alice@example.com

# Update encrypted files with the new key
secretenv rewrap
```

There is no need to immediately remove the old `kid` from `known_keys`. `known_keys` is merely a verification history — `members/active` is what determines whether a `kid` belongs to a current member.

### 6.5 Reading artifacts from a departed signer

Artifacts signed by a former member who has been removed from `members/active` are rejected on the normal read path. When a one-time exception read is needed, **non-member acceptance** is offered interactively.

```
Non-member acceptance for signer:
  member_id: ex-member@example.com
  kid: 5FT8K3N2...
  ...
Accept this artifact one time only? [y/N]
```

This acceptance:
- Is **one-time only** — re-confirmation is required next time
- Does not update `known_keys`
- Does not restore the signer to active status

---

## 7. Trust Store Management Commands

The following commands operate only on the user-local approval cache. They do not affect `members/active` or any team state.

### `trust list` — List approved keys

```bash
secretenv trust list
```

### `trust remove <kid>` — Revoke approval for a specific key

```bash
secretenv trust remove 7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD
```

`trust remove` does not remove the member from the team. It simply means that the next time the `kid` is encountered, interactive approval will be requested again.

Use cases: correcting a mistaken approval, refreshing verification, etc.

### `trust purge --older-than <duration>` — Bulk removal of old approvals

```bash
# Remove approvals older than 180 days
secretenv trust purge --older-than 180d

# Skip the confirmation prompt (for CI, etc.)
secretenv trust purge --older-than 180d --force
```

In interactive execution, a preview of items to be removed and a confirmation prompt are shown. Non-interactive execution requires `-f` or `--force`.

Periodic purging clears out stale approvals and prompts re-verification.

---

## 8. CI/CD Usage

### `SECRETENV_STRICT_KEY_CHECKING=no`

In non-interactive environments such as CI, interactive approval is not possible. Setting `SECRETENV_STRICT_KEY_CHECKING=no` allows the `known_keys` check to be skipped **for the read path only**.

```bash
SECRETENV_STRICT_KEY_CHECKING=no secretenv get DB_PASSWORD
SECRETENV_STRICT_KEY_CHECKING=no secretenv run -- ./deploy.sh
```

**What is skipped:**
- The `known_keys` approval check (read path only)

**What is NOT skipped:**
- Cryptographic signature verification
- `signer_pub` verification
- `members/active` member check

**Caution:**
- **Does not apply to the write path**. `encrypt` / `set` / `rewrap` still require approval for all recipients
- Not recommended for use on an unreviewed clone immediately after bootstrap
- Use only in trusted CI environments where a proper review process for `members/active` is in place

---

## 9. Trust Store Location

```text
${SECRETENV_HOME:-~/.config/secretenv}/trust/<owner_member_id>.json
```

- Located outside the repository, so it is not tracked by Git
- The same approval cache can be reused across clones and branches
- The file is signed with the owner's key, enabling detection of tampering or corruption

---

## 10. Before and After Comparison

| Aspect | Previous | This update |
|--------|----------|-------------|
| Signature verification | Embedded `signer_pub` | Same |
| Member determination | `members/active` | Same |
| Handling unverified keys | Ad-hoc verification, or passing without verification | Interactive approval required |
| Recording verification results | None | Saved in `known_keys` |
| Cross-workspace approval | None | Reused via the same trust store |
| Additional read-path condition | None | Signer `kid` must be approved |
| Additional write-path condition | None | All recipient `kid`s must be approved |
| Trust store management | None | `trust list` / `remove` / `purge` |

---

## 11. Important Considerations

### Limitations of TOFU (Trust On First Use)

The local trust store adopts a TOFU model similar to SSH's known_hosts. If you approve an incorrect key during the initial approval, that mistake is cached. There is no cryptographic mechanism to prevent this.

During initial approval, it is critical to **verify the `kid` and GitHub account id through a separate channel (Slack, video call, in person)**.

### `members/active` depends on repo governance

`members/active` is the criterion for member determination, but it is data in the repository. Git access controls and a PR review process are prerequisites for trust.

### The local trust store is a local file

The trust store can detect integrity issues via signatures, but the security of the local filesystem depends on OS-level security.

---

## 12. Summary

The local trust store does not change the fundamental philosophy of secretenv.

- Do not blindly trust the workspace
- Each user participates in acceptance decisions
- The tool presents the materials for judgment

What changes is simply that **verification results can now be saved locally and reused**.

Key migration points:

1. **Run `member verify --approve` first** to approve existing members' keys
2. Daily operations feel the same as before when all keys are approved
3. An interactive approval prompt appears when an unverified key is encountered — this is a necessary check for safety
4. Use `trust list` / `trust remove` / `trust purge` to manage the approval cache
5. In CI, use `SECRETENV_STRICT_KEY_CHECKING=no` to skip the read-path approval check
