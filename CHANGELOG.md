# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries before 0.99.0-beta were reconstructed from the commit history and are
summarized rather than exhaustive.

## [Unreleased]

### Security

- Ed25519 signature verification is now strict, rejecting small-order verifying
  keys and small-order signature points. A small-order key has no private key
  holder and makes one signature verify against arbitrary messages, which
  emptied the key consistency property of the public key self-signature.
- `inspect` no longer aborts on an artifact whose attestation key ends with a
  multi-byte character at the truncation point, and no longer lets a newline in
  that field forge additional output lines. Inspection formats a document
  before verifying its signature, so those fields are attacker-controlled.
- The attestation key is constrained to a single line in the schema.
- The installer pins the signer workflow when verifying build provenance, so an
  attestation produced by another workflow in the repository is refused.
- CI runs cargo-deny over advisories, licenses, sources, and wildcard
  dependencies.
- The ssh-agent client bounds the identity count declared by a response before
  allocating for it.
- The GitHub API client refuses redirects, bounds response bodies, and pins the
  API version.

### Fixed

- Writes are synced to storage before returning. The keystore and local trust
  store previously relied on a rename that could reach disk ahead of the file
  contents.
- The documented limit of 1000 wrap items is reachable. The pre-parse element
  scan capped documents at roughly 907 recipients and reported an unrelated
  cause.
- `KAPSARO_SSH_IDENTITY` expands a leading tilde, matching the config file.
- Release builds unwind instead of aborting, so the Drop implementations that
  zeroize secret material and clear credential environment variables still run
  on a panic path.

### Added

- Backward compatibility fixtures recorded from 0.99.2-beta, verified and
  decrypted through the public API on every build.
- Known-answer tests against RFC 9180 Appendix A.2 and RFC 8032 section 7.1.
- Tests run on macOS in addition to Linux.

### Documentation

- The security design records the concrete input limits, separating the wire
  contract from implementation guards.

## [0.99.2-beta] - 2026-07-13

### Added

- CLI errors carry structured reason and options guidance.

### Fixed

- Concurrent mutations are routed through a directory file descriptor, closing
  a time-of-check-to-time-of-use gap.

## [0.99.1-beta] - 2026-06-02

### Fixed

- Release URLs are derived from the repository context, and `SHA256SUMS` is
  validated before the Homebrew formula is updated.

## [0.99.0-beta] - 2026-06-02

### Added

- Release provenance is published as GitHub Artifact Attestations, and the
  installer verifies it by default.

### Changed

- The project was renamed from SecretEnv to kapsaro.
- Domain separation context strings were given their present format.

## [0.10.1-alpha] - 2026-06-01

### Added

- `--allow-non-member` is required to start the non-member signer acceptance
  flow.
- `list` performs full read-path trust verification.

### Changed

- The PublicKey format moved to v7 with a flattened keys and attestation
  structure.
- The default export password minimum rose to 20 bytes.
- Errors and warnings use a structured multi-line format.

## [0.9.1-alpha] - 2026-05-21

### Added

- HMAC-SHA256 key possession proof in artifact signatures.
- The kv-enc format moved to v7 with per-entry CEK key binding.
- `doctor` command for workspace diagnostics.

### Security

- The key possession HMAC is bound to the signer key statement ID.
- The release workflow gained a pre-publish verification gate.

## [0.7.1-alpha] - 2026-04-23

### Added

- `--stdin` and `--stdout` for `encrypt` and `decrypt`.
- `--target` for selective rewrapping.

## [0.4.1-alpha] - 2026-04-12

### Added

- Local trust store for approval caching.
- Content-derived key statement IDs, replacing ULIDs.
- Offline verification of member files.
- Affected-artifact preview and confirmation on member removal.

## [0.1.1-alpha] - 2026-03-20

First tagged release.

[Unreleased]: https://github.com/ebisawa/kapsaro/compare/v0.99.2-beta...HEAD
[0.99.2-beta]: https://github.com/ebisawa/kapsaro/compare/v0.99.1-beta...v0.99.2-beta
[0.99.1-beta]: https://github.com/ebisawa/kapsaro/compare/v0.99.0-beta...v0.99.1-beta
[0.99.0-beta]: https://github.com/ebisawa/kapsaro/compare/v0.10.1-alpha...v0.99.0-beta
[0.10.1-alpha]: https://github.com/ebisawa/kapsaro/compare/v0.9.1-alpha...v0.10.1-alpha
[0.9.1-alpha]: https://github.com/ebisawa/kapsaro/compare/v0.7.1-alpha...v0.9.1-alpha
[0.7.1-alpha]: https://github.com/ebisawa/kapsaro/compare/v0.4.1-alpha...v0.7.1-alpha
[0.4.1-alpha]: https://github.com/ebisawa/kapsaro/compare/v0.1.1-alpha...v0.4.1-alpha
[0.1.1-alpha]: https://github.com/ebisawa/kapsaro/releases/tag/v0.1.1-alpha
