// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for SSH module (fingerprint, agent, verify).
//!
//! Test structure follows TDD approach:
//! - Phase 4.1: fingerprint (SHA256 fingerprint calculation)
//! - Phase 4.2: agent (ssh-agent signature + determinism check)
//! - Phase 4.3: verify (SSHSIG verification via ssh-keygen)

use secretenv::io::ssh::protocol::fingerprint::build_sha256_fingerprint;
use secretenv::Error;

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

/// Test: Invalid public key format returns error.
///
/// Missing key type or base64 data should fail.
#[test]
fn test_invalid_pubkey_format_error() {
    let invalid_pubkeys = vec![
        "not-a-valid-pubkey",
        secretenv::io::ssh::protocol::constants::KEY_TYPE_ED25519,
        "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
        "",
    ];

    for pubkey in invalid_pubkeys {
        let result = build_sha256_fingerprint(pubkey);
        assert!(result.is_err(), "Expected error for pubkey: {}", pubkey);

        if let Err(Error::Ssh { message, .. }) = result {
            assert!(
                message.contains("Invalid")
                    || message.contains("invalid")
                    || message.contains("empty"),
                "Unexpected error message for '{}': {}",
                pubkey,
                message
            );
        } else {
            panic!("Expected Error::Ssh variant for: {}", pubkey);
        }
    }
}

/// Test: Unsupported key type (RSA) returns error.
///
/// v1 only supports ed25519.
#[test]
fn test_unsupported_key_type_rsa_error() {
    let rsa_pubkey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDabc123 user@example.com";

    let result = build_sha256_fingerprint(rsa_pubkey);

    assert!(result.is_err());
    if let Err(Error::Ssh { message, .. }) = result {
        assert!(
            message.contains(secretenv::io::ssh::protocol::constants::KEY_TYPE_ED25519)
                || message.contains("Unsupported")
        );
    } else {
        panic!("Expected Error::Ssh variant");
    }
}

/// Test: Empty public key returns error.
#[test]
fn test_empty_pubkey_error() {
    let result = build_sha256_fingerprint("");

    assert!(result.is_err());
    if let Err(Error::Ssh { message, .. }) = result {
        assert!(message.contains("empty") || message.contains("Invalid"));
    } else {
        panic!("Expected Error::Ssh variant");
    }
}

/// Test: Malformed base64 returns error.
///
/// Invalid characters in base64 data should fail.
#[test]
fn test_malformed_base64_error() {
    let bad_pubkey = "ssh-ed25519 !!!invalid-base64!!! comment";

    let result = build_sha256_fingerprint(bad_pubkey);

    assert!(result.is_err());
    if let Err(Error::Ssh { message, .. }) = result {
        assert!(message.contains("base64") || message.contains("decode"));
    } else if let Err(Error::Parse { .. }) = result {
        // Also acceptable
    } else {
        panic!("Expected Error::Ssh or Error::Parse variant");
    }
}

/// Test: extract_key_blob successfully parses valid public key.
///
/// This tests the internal helper function (if exposed for testing).
#[test]
fn test_extract_key_blob() {
    let pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com";

    // Note: extract_key_blob may not be public API.
    // If it's internal, this test can be removed or adapted.
    // For now, we test via build_sha256_fingerprint which uses it.
    let result = build_sha256_fingerprint(pubkey);
    assert!(result.is_ok());
}

/// Test: hash_and_encode produces Base64NoPad without padding.
///
/// This tests the internal helper function (if exposed for testing).
#[test]
fn test_hash_and_encode_no_padding() {
    let pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    let result = build_sha256_fingerprint(pubkey);

    assert!(result.is_ok());
    let fingerprint = result.unwrap();

    // Verify no padding '=' in the Base64 part
    assert!(!fingerprint.contains('='));
}

// ============================================================================
// Phase 4.2: SSH Agent Tests (placeholder)
// ============================================================================

// Tests for ssh-agent signature will be added in Phase 4.2.

// ============================================================================
// Phase 4.3: SSHSIG Verify Tests (placeholder)
// ============================================================================

// Tests for SSHSIG verification will be added in Phase 4.3.
