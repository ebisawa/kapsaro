// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for SSH module (fingerprint, agent, verify).
//!
//! Test structure follows TDD approach:
//! - Phase 4.1: fingerprint (SHA256 fingerprint calculation)
//! - Phase 4.2: agent (ssh-agent signature + determinism check)
//! - Phase 4.3: verify (SSHSIG verification via ssh-keygen)

use kapsaro_core::cli_api::test_support::storage::ssh::protocol::fingerprint::build_sha256_fingerprint;

// ============================================================================
// Phase 4.1: SSH Fingerprint Tests
// ============================================================================

/// Test: build_sha256_fingerprint returns deterministic results.
///
/// Given the same public key, the fingerprint should always be identical.
#[test]
fn test_build_sha256_fingerprint_deterministic() {
    let pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com";

    let result1 = build_sha256_fingerprint(pubkey);
    let result2 = build_sha256_fingerprint(pubkey);

    assert!(result1.is_ok());
    assert!(result2.is_ok());
    assert_eq!(result1.unwrap(), result2.unwrap());
}

/// Test: Fingerprint format validation (SHA256: prefix + Base64NoPad).
///
/// Format must be "SHA256:" + Base64NoPad (43 chars).
#[test]
fn test_fingerprint_format_validation() {
    let pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    let result = build_sha256_fingerprint(pubkey);

    assert!(result.is_ok());
    let fingerprint = result.unwrap();

    // Must start with "SHA256:"
    assert!(fingerprint.starts_with("SHA256:"));

    // Base64 part should not contain padding '='
    let b64_part = &fingerprint["SHA256:".len()..]; // Skip "SHA256:"
    assert!(!b64_part.contains('='));

    // Base64 characters only (A-Za-z0-9+/)
    assert!(b64_part
        .chars()
        .all(|c: char| c.is_ascii_alphanumeric() || c == '+' || c == '/'));
}

/// Test: Fingerprint length is exactly 50 characters (SHA256: + 43 chars).
///
/// SHA256 hash = 32 bytes -> Base64NoPad = 43 chars -> Total = 7 + 43 = 50.
#[test]
fn test_fingerprint_length_43_chars() {
    let pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    let result = build_sha256_fingerprint(pubkey);

    assert!(result.is_ok());
    let fingerprint = result.unwrap();

    // "SHA256:" (7) + Base64NoPad (43) = 50 total
    assert_eq!(fingerprint.len(), 50);

    // Base64 part should be exactly 43 characters
    let b64_part = &fingerprint["SHA256:".len()..];
    assert_eq!(b64_part.len(), 43);
}

/// Test: Comment is excluded from fingerprint calculation.
///
/// Comment must not affect fingerprint.
#[test]
fn test_comment_excluded_from_fingerprint() {
    let pubkey1 =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let pubkey2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com";
    let pubkey3 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl another-comment";

    let result1 = build_sha256_fingerprint(pubkey1);
    let result2 = build_sha256_fingerprint(pubkey2);
    let result3 = build_sha256_fingerprint(pubkey3);

    assert!(result1.is_ok());
    assert!(result2.is_ok());
    assert!(result3.is_ok());

    // All three should produce the same fingerprint
    let fpr1 = result1.unwrap();
    let fpr2 = result2.unwrap();
    let fpr3 = result3.unwrap();
    assert_eq!(fpr1, fpr2);
    assert_eq!(fpr2, fpr3);
}

// ============================================================================
// Phase 4.2: SSH Agent Tests (placeholder)
// ============================================================================

// Tests for ssh-agent signature will be added in Phase 4.2.

// ============================================================================
// Phase 4.3: SSHSIG Verify Tests (placeholder)
// ============================================================================

// Tests for SSHSIG verification will be added in Phase 4.3.
