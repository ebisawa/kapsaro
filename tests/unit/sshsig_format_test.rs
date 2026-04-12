// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for SSHSIG format parsing (Phase 11.1 - TDD Red phase)

use secretenv::io::ssh::protocol::sshsig::{
    build_sshsig_signed_data, parse_sshsig_armored, parse_sshsig_blob, SSHSIG_HASHALG,
    SSHSIG_MAGIC, SSHSIG_NAMESPACE,
};
use secretenv::io::ssh::protocol::wire::ssh_string_encode;
use secretenv::support::codec::base64_public::encode_base64_standard;
use sha2::{Digest, Sha256};

#[test]
fn test_build_sshsig_signed_data_format() {
    let message = b"test message";
    let result = build_sshsig_signed_data(message);

    // Check magic
    assert_eq!(&result[0..6], SSHSIG_MAGIC);

    // Check it contains namespace
    let result_str = String::from_utf8_lossy(&result);
    assert!(result_str.contains(SSHSIG_NAMESPACE));
}

#[test]
fn test_build_sshsig_signed_data_includes_hash() {
    let message = b"test";
    let result = build_sshsig_signed_data(message);

    let hash = Sha256::digest(message);
    // Hash should be in the output (as SSH_STRING)
    assert!(result.windows(hash.len()).any(|w| w == hash.as_slice()));
}

#[test]
fn test_build_sshsig_signed_data_deterministic() {
    let message = b"determinism test";
    let result1 = build_sshsig_signed_data(message);
    let result2 = build_sshsig_signed_data(message);

    assert_eq!(
        result1, result2,
        "build_sshsig_signed_data must be deterministic"
    );
}

#[test]
fn test_build_sshsig_signed_data_contains_hashalg() {
    let message = b"hashalg test";
    let result = build_sshsig_signed_data(message);

    let result_str = String::from_utf8_lossy(&result);
    assert!(result_str.contains(SSHSIG_HASHALG));
}

#[test]
fn test_parse_sshsig_blob_valid() {
    // Construct a valid SSHSIG blob manually

    let mut blob = Vec::new();
    blob.extend_from_slice(b"SSHSIG"); // magic
    blob.extend_from_slice(&1u32.to_be_bytes()); // version

    blob.extend_from_slice(&ssh_string_encode(
        b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicKeyData123456789",
    )); // pubkey
    blob.extend_from_slice(&ssh_string_encode(SSHSIG_NAMESPACE.as_bytes())); // namespace
    blob.extend_from_slice(&ssh_string_encode(b"")); // reserved (empty)
    blob.extend_from_slice(&ssh_string_encode(b"sha256")); // hashalg
    blob.extend_from_slice(&ssh_string_encode(b"signature_data_here")); // signature

    let signature = parse_sshsig_blob(&blob).unwrap();
    assert_eq!(signature.as_bytes(), b"signature_data_here");
}

#[test]
fn test_parse_sshsig_blob_invalid_magic() {
    let blob = b"WRONGMAGIC";
    let result = parse_sshsig_blob(blob);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("magic") || err_msg.contains("SSHSIG"));
}

#[test]
fn test_parse_sshsig_blob_too_short() {
    let blob = b"SSH"; // Only 3 bytes
    let result = parse_sshsig_blob(blob);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("short") || err_msg.contains("Insufficient"));
}

#[test]
fn test_parse_sshsig_blob_wrong_version() {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"SSHSIG");
    blob.extend_from_slice(&999u32.to_be_bytes()); // wrong version

    let result = parse_sshsig_blob(&blob);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("version") || err_msg.contains("999"));
}

#[test]
fn test_parse_sshsig_blob_wrong_namespace() {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"SSHSIG");
    blob.extend_from_slice(&1u32.to_be_bytes());

    blob.extend_from_slice(&ssh_string_encode(b"ssh-ed25519 AAAA..."));
    blob.extend_from_slice(&ssh_string_encode(b"wrong.namespace")); // wrong!

    let result = parse_sshsig_blob(&blob);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("namespace") || err_msg.contains("mismatch"));
}

#[test]
fn test_parse_sshsig_blob_non_empty_reserved() {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"SSHSIG");
    blob.extend_from_slice(&1u32.to_be_bytes());

    blob.extend_from_slice(&ssh_string_encode(b"ssh-ed25519 AAAA..."));
    blob.extend_from_slice(&ssh_string_encode(SSHSIG_NAMESPACE.as_bytes()));
    blob.extend_from_slice(&ssh_string_encode(b"not_empty")); // reserved must be empty!

    let result = parse_sshsig_blob(&blob);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("reserved") || err_msg.contains("empty"));
}

#[test]
fn test_parse_sshsig_blob_wrong_hashalg() {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"SSHSIG");
    blob.extend_from_slice(&1u32.to_be_bytes());

    blob.extend_from_slice(&ssh_string_encode(b"ssh-ed25519 AAAA..."));
    blob.extend_from_slice(&ssh_string_encode(SSHSIG_NAMESPACE.as_bytes()));
    blob.extend_from_slice(&ssh_string_encode(b""));
    blob.extend_from_slice(&ssh_string_encode(b"sha512")); // wrong hash algorithm!

    let result = parse_sshsig_blob(&blob);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("hash") || err_msg.contains("sha"));
}

#[test]
fn test_parse_sshsig_armored_valid() {
    // Real SSHSIG armored format (base64-encoded valid blob)
    let mut blob = Vec::new();
    blob.extend_from_slice(b"SSHSIG");
    blob.extend_from_slice(&1u32.to_be_bytes());
    blob.extend_from_slice(&ssh_string_encode(b"ssh-ed25519 AAAA..."));
    blob.extend_from_slice(&ssh_string_encode(SSHSIG_NAMESPACE.as_bytes()));
    blob.extend_from_slice(&ssh_string_encode(b""));
    blob.extend_from_slice(&ssh_string_encode(b"sha256"));
    blob.extend_from_slice(&ssh_string_encode(b"test_signature_ikm"));

    let b64 = encode_base64_standard(&blob);
    let armored = format!(
        "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----",
        b64
    );

    let result = parse_sshsig_armored(&armored).unwrap();
    assert_eq!(result.as_bytes(), b"test_signature_ikm");
}

#[test]
fn test_parse_sshsig_armored_multiline_base64() {
    // Test with line-wrapped base64
    let mut blob = Vec::new();
    blob.extend_from_slice(b"SSHSIG");
    blob.extend_from_slice(&1u32.to_be_bytes());
    blob.extend_from_slice(&ssh_string_encode(b"ssh-ed25519 AAAA..."));
    blob.extend_from_slice(&ssh_string_encode(SSHSIG_NAMESPACE.as_bytes()));
    blob.extend_from_slice(&ssh_string_encode(b""));
    blob.extend_from_slice(&ssh_string_encode(b"sha256"));
    blob.extend_from_slice(&ssh_string_encode(b"multiline_test"));

    let b64 = encode_base64_standard(&blob);
    // Split into 64-char lines (typical SSH format)
    let lines: Vec<String> = b64
        .as_bytes()
        .chunks(64)
        .map(|chunk| String::from_utf8(chunk.to_vec()).unwrap())
        .collect();

    let armored = format!(
        "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----",
        lines.join("\n")
    );

    let result = parse_sshsig_armored(&armored).unwrap();
    assert_eq!(result.as_bytes(), b"multiline_test");
}

#[test]
fn test_parse_sshsig_armored_no_markers() {
    let result = parse_sshsig_armored("just random text without markers");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    // The error message should mention base64 or content (case-insensitive)
    // Actual message: "SSH error: Base64 decode failed: ..."
    let err_lower = err_msg.to_lowercase();
    assert!(
        err_lower.contains("base64")
            || err_lower.contains("content")
            || err_lower.contains("decode"),
        "Error message should mention base64, content, or decode, got: {}",
        err_msg
    );
}

#[test]
fn test_parse_sshsig_armored_invalid_base64() {
    let armored =
        "-----BEGIN SSH SIGNATURE-----\n!!!invalid_base64!!!\n-----END SSH SIGNATURE-----";
    let result = parse_sshsig_armored(armored);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("base64") || err_msg.contains("decode"));
}

// Additional tests from src/io/ssh/protocol/sshsig.rs
#[test]
fn test_build_sshsig_signed_data_structure() {
    let message = b"test";
    let result = build_sshsig_signed_data(message);

    // Check magic
    assert_eq!(&result[0..6], SSHSIG_MAGIC);

    // Should contain namespace
    let result_str = String::from_utf8_lossy(&result);
    assert!(result_str.contains(SSHSIG_NAMESPACE));

    // Should contain hash algorithm
    assert!(result_str.contains(SSHSIG_HASHALG));
}

#[test]
fn test_parse_sshsig_blob_roundtrip() {
    // Construct a minimal valid SSHSIG blob
    let mut blob = Vec::new();
    blob.extend_from_slice(SSHSIG_MAGIC);
    blob.extend_from_slice(&1u32.to_be_bytes());
    blob.extend_from_slice(&ssh_string_encode(b"ssh-ed25519 AAAA..."));
    blob.extend_from_slice(&ssh_string_encode(SSHSIG_NAMESPACE.as_bytes()));
    blob.extend_from_slice(&ssh_string_encode(b""));
    blob.extend_from_slice(&ssh_string_encode(b"sha256"));
    blob.extend_from_slice(&ssh_string_encode(b"test_signature_ikm"));

    let signature = parse_sshsig_blob(&blob).unwrap();
    assert_eq!(signature.as_bytes(), b"test_signature_ikm");
}
