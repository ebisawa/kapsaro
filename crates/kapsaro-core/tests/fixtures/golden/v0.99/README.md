# Golden artifacts for kapsaro 0.99

## Warning: the private keys here are test-only

`id_ed25519` and `private.json` are committed on purpose so that the backward
compatibility test can decrypt the recorded artifacts. They protect nothing.
Never reuse them, never add them to an SSH agent, and never treat a workspace
that lists this `kid` as trusted.

## Purpose

These files record what kapsaro 0.99.2-beta actually wrote. The compatibility
test decrypts and verifies them with the current code, so a change that breaks
the stored wire format fails the build instead of silently orphaning artifacts
that teams already committed to their repositories.

Runtime-generated fixtures cannot catch this: they regenerate the artifact and
verify it with the same build, so producer and consumer always agree.

## Contents

| File | Description |
|------|-------------|
| `id_ed25519` | Passphrase-less SSH key that protects the private key document |
| `id_ed25519.pub` | Matching public key |
| `public.json` | PublicKey document for `alice@example.com` |
| `private.json` | PrivateKey document, protected by the SSH key above |
| `file_enc.json` | file-enc artifact |
| `kv_enc.kvenc` | kv-enc artifact holding two entries |
| `expected.json` | Plaintext, kid, and entry values the artifacts must yield |

## Rules

This directory is append-only. Do not regenerate or edit these files. A
regenerated artifact records the current build rather than the released one,
which removes the only property that makes the fixture useful.

When the wire format gains a new version, add a sibling directory such as
`v1.0/` with its own compatibility test and leave this one untouched.

The key expires in 2126 so the test exercises the same code path regardless of
when it runs.

## How these were produced

The artifact-producing sources at `v0.99.2-beta` and at the commit that added
this directory are identical; the only manifest difference is the release
panic strategy, which does not affect output. The recorded files therefore
match what the released build writes.

```sh
ssh-keygen -t ed25519 -N "" -C "kapsaro-golden-fixture-do-not-use" -f id_ed25519

kapsaro key new --home "$HOME_DIR" --ssh-keygen -i id_ed25519 \
  -m alice@example.com --expires-at 2126-01-01T00:00:00Z
kapsaro init --home "$HOME_DIR" -w "$WS" --ssh-keygen -i id_ed25519 \
  -m alice@example.com

printf 'GOLDEN_FIXTURE_PLAINTEXT\n' > sample.txt
kapsaro encrypt --home "$HOME_DIR" -w "$WS" --ssh-keygen -i id_ed25519 \
  -m alice@example.com -o file_enc.json sample.txt

kapsaro set --home "$HOME_DIR" -w "$WS" --ssh-keygen -i id_ed25519 \
  -m alice@example.com DATABASE_URL 'postgres://user:pw@localhost/golden'
kapsaro set --home "$HOME_DIR" -w "$WS" --ssh-keygen -i id_ed25519 \
  -m alice@example.com API_KEY 'sk-golden-fixture-value'
```

`sid`, nonces, and HPKE encapsulated keys are random. That is expected: these
files are a recording, not a reproducible build target.
