// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for SSH fingerprint utilities

use secretenv::io::ssh::protocol::fingerprint::build_sha256_fingerprint;

const TEST_PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

#[test]
fn test_fingerprint_format() {
    let fp = build_sha256_fingerprint(TEST_PUBKEY).unwrap();
    assert!(fp.starts_with("SHA256:"));
    assert_eq!(fp.len(), 50);
    assert!(!fp.contains('='));
}

#[test]
fn test_fingerprint_with_comment() {
    let pubkey = format!("{} user@example.com", TEST_PUBKEY);
    let fp = build_sha256_fingerprint(&pubkey).unwrap();
    assert!(fp.starts_with("SHA256:"));
}

#[test]
fn test_fingerprint_deterministic() {
    let fp1 = build_sha256_fingerprint(TEST_PUBKEY).unwrap();
    let fp2 = build_sha256_fingerprint(TEST_PUBKEY).unwrap();
    assert_eq!(fp1, fp2);
}

#[test]
fn test_error_empty() {
    let err = build_sha256_fingerprint("").unwrap_err();
    assert!(err.to_string().contains("empty"));
}

#[test]
fn test_error_invalid_format() {
    let err = build_sha256_fingerprint(secretenv::io::ssh::protocol::constants::KEY_TYPE_ED25519)
        .unwrap_err();
    assert!(err.to_string().contains("Invalid"));
}

#[test]
fn test_error_unsupported_key_type() {
    let err = build_sha256_fingerprint("ssh-rsa AAAAB3NzaC1yc2E...").unwrap_err();
    assert!(err.to_string().contains("Unsupported"));
}
