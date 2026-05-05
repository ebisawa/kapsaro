// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for SSH public key parsing
//!
//! Tests for decode_ssh_public_key_blob function

use secretenv::io::ssh::protocol::parse::decode_ssh_public_key_blob;

const TEST_PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

#[test]
fn test_parse_ssh_pubkey_valid() {
    let blob = decode_ssh_public_key_blob(&format!("{} user@example.com", TEST_PUBKEY)).unwrap();
    assert_eq!(blob.len(), 51);
}

#[test]
fn test_parse_ssh_pubkey_no_comment() {
    assert!(decode_ssh_public_key_blob(TEST_PUBKEY).is_ok());
}

#[test]
fn test_parse_ssh_pubkey_empty() {
    assert!(decode_ssh_public_key_blob("")
        .unwrap_err()
        .to_string()
        .contains("empty"));
}

#[test]
fn test_parse_ssh_pubkey_invalid_format() {
    assert!(
        decode_ssh_public_key_blob(secretenv::io::ssh::protocol::constants::KEY_TYPE_ED25519)
            .unwrap_err()
            .to_string()
            .contains("Invalid")
    );
}

#[test]
fn test_parse_ssh_pubkey_unsupported_type() {
    assert!(decode_ssh_public_key_blob("ssh-rsa AAAA...")
        .unwrap_err()
        .to_string()
        .contains("Unsupported"));
}

#[test]
fn test_parse_ssh_pubkey_invalid_base64() {
    assert!(decode_ssh_public_key_blob(&format!(
        "{} !!!invalid!!!",
        secretenv::io::ssh::protocol::constants::KEY_TYPE_ED25519
    ))
    .unwrap_err()
    .to_string()
    .contains("base64"));
}
