// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for SSHSIG format parsing (Phase 11.1 - TDD Red phase)

use secretenv::io::ssh::protocol::constants::{ATTESTATION_NAMESPACE, KEY_PROTECTION_NAMESPACE};
use secretenv::io::ssh::protocol::parse::decode_ssh_public_key_blob;
use secretenv::io::ssh::protocol::sshsig::{
    build_sshsig_signed_data, parse_sshsig_armored, parse_sshsig_blob, SSHSIG_HASHALG, SSHSIG_MAGIC,
};
use secretenv::io::ssh::protocol::types::SshsigBlob;
use secretenv::io::ssh::protocol::wire::encode_ssh_string;
use secretenv::support::codec::base64_public::encode_base64_standard;
use sha2::{Digest, Sha256};

const TEST_SSH_PUBKEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com";
const OTHER_SSH_PUBKEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkB6jid+Y/7wt0S+9jTJGX1UytxIHOO3GXVPZPY1OYT other@example.com";

fn append_publickey(blob: &mut Vec<u8>, ssh_pubkey: &str) {
    let publickey = decode_ssh_public_key_blob(ssh_pubkey).unwrap();
    blob.extend_from_slice(&encode_ssh_string(&publickey));
}

fn build_sshsig_blob_with_raw_signature(ssh_pubkey: &str, raw_sig: [u8; 64]) -> Vec<u8> {
    let mut signature_blob = Vec::new();
    signature_blob.extend_from_slice(&encode_ssh_string(b"ssh-ed25519"));
    signature_blob.extend_from_slice(&encode_ssh_string(&raw_sig));

    let mut blob = Vec::new();
    blob.extend_from_slice(SSHSIG_MAGIC);
    blob.extend_from_slice(&1u32.to_be_bytes());
    append_publickey(&mut blob, ssh_pubkey);
    blob.extend_from_slice(&encode_ssh_string(KEY_PROTECTION_NAMESPACE.as_bytes()));
    blob.extend_from_slice(&encode_ssh_string(b""));
    blob.extend_from_slice(&encode_ssh_string(b"sha256"));
    blob.extend_from_slice(&encode_ssh_string(&signature_blob));
    blob
}

#[test]
fn test_build_sshsig_signed_data_format() {
    let message = b"test message";
    let result = build_sshsig_signed_data(message, KEY_PROTECTION_NAMESPACE);

    // Check magic
    assert_eq!(&result[0..6], SSHSIG_MAGIC);

    // Check it contains namespace
    let result_str = String::from_utf8_lossy(&result);
    assert!(result_str.contains(KEY_PROTECTION_NAMESPACE));
}

#[test]
fn test_build_sshsig_signed_data_includes_hash() {
    let message = b"test";
    let result = build_sshsig_signed_data(message, KEY_PROTECTION_NAMESPACE);

    let hash = Sha256::digest(message);
    // Hash should be in the output (as SSH_STRING)
    assert!(result.windows(hash.len()).any(|w| w == hash.as_slice()));
}

#[test]
fn test_build_sshsig_signed_data_deterministic() {
    let message = b"determinism test";
    let result1 = build_sshsig_signed_data(message, KEY_PROTECTION_NAMESPACE);
    let result2 = build_sshsig_signed_data(message, KEY_PROTECTION_NAMESPACE);

    assert_eq!(
        result1, result2,
        "build_sshsig_signed_data must be deterministic"
    );
}

#[test]
fn test_build_sshsig_signed_data_contains_hashalg() {
    let message = b"hashalg test";
    let result = build_sshsig_signed_data(message, KEY_PROTECTION_NAMESPACE);

    let result_str = String::from_utf8_lossy(&result);
    assert!(result_str.contains(SSHSIG_HASHALG));
}

#[test]
fn test_parse_sshsig_blob_valid() {
    // Construct a valid SSHSIG blob manually

    let mut blob = Vec::new();
    blob.extend_from_slice(b"SSHSIG"); // magic
    blob.extend_from_slice(&1u32.to_be_bytes()); // version

    append_publickey(&mut blob, TEST_SSH_PUBKEY);
    blob.extend_from_slice(&encode_ssh_string(KEY_PROTECTION_NAMESPACE.as_bytes())); // namespace
    blob.extend_from_slice(&encode_ssh_string(b"")); // reserved (empty)
    blob.extend_from_slice(&encode_ssh_string(b"sha256")); // hashalg
    blob.extend_from_slice(&encode_ssh_string(b"signature_data_here")); // signature

    let signature = parse_sshsig_blob(&blob, KEY_PROTECTION_NAMESPACE, TEST_SSH_PUBKEY).unwrap();
    assert_eq!(signature.as_bytes(), b"signature_data_here");
}

#[test]
fn test_sshsig_blob_extract_ed25519_raw_signature() {
    let mut raw_sig = [0u8; 64];
    for (index, byte) in raw_sig.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let blob = SshsigBlob::new(build_sshsig_blob_with_raw_signature(
        TEST_SSH_PUBKEY,
        raw_sig,
    ));

    let extracted = blob
        .extract_ed25519_raw(KEY_PROTECTION_NAMESPACE, TEST_SSH_PUBKEY)
        .unwrap();

    assert_eq!(extracted.as_bytes(), &raw_sig);
}

#[test]
fn test_sshsig_blob_extract_ed25519_rejects_publickey_mismatch() {
    let blob = SshsigBlob::new(build_sshsig_blob_with_raw_signature(
        OTHER_SSH_PUBKEY,
        [7u8; 64],
    ));

    let err = blob
        .extract_ed25519_raw(KEY_PROTECTION_NAMESPACE, TEST_SSH_PUBKEY)
        .unwrap_err()
        .to_string();

    assert!(err.contains("publickey"));
}

#[test]
fn test_parse_sshsig_blob_invalid_magic() {
    let blob = b"WRONGMAGIC";
    let result = parse_sshsig_blob(blob, KEY_PROTECTION_NAMESPACE, TEST_SSH_PUBKEY);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("magic") || err_msg.contains("SSHSIG"));
}

#[test]
fn test_parse_sshsig_blob_too_short() {
    let blob = b"SSH"; // Only 3 bytes
    let result = parse_sshsig_blob(blob, KEY_PROTECTION_NAMESPACE, TEST_SSH_PUBKEY);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("short") || err_msg.contains("Insufficient"));
}

#[test]
fn test_parse_sshsig_blob_wrong_version() {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"SSHSIG");
    blob.extend_from_slice(&999u32.to_be_bytes()); // wrong version

    let result = parse_sshsig_blob(&blob, KEY_PROTECTION_NAMESPACE, TEST_SSH_PUBKEY);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("version") || err_msg.contains("999"));
}

#[test]
fn test_parse_sshsig_blob_rejects_publickey_mismatch() {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"SSHSIG");
    blob.extend_from_slice(&1u32.to_be_bytes());

    append_publickey(&mut blob, OTHER_SSH_PUBKEY);
    blob.extend_from_slice(&encode_ssh_string(KEY_PROTECTION_NAMESPACE.as_bytes()));
    blob.extend_from_slice(&encode_ssh_string(b""));
    blob.extend_from_slice(&encode_ssh_string(b"sha256"));
    blob.extend_from_slice(&encode_ssh_string(b"signature_data_here"));

    let result = parse_sshsig_blob(&blob, KEY_PROTECTION_NAMESPACE, TEST_SSH_PUBKEY);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("publickey") || err_msg.contains("fingerprint"),
        "error should mention publickey mismatch, got: {}",
        err_msg
    );
}

#[test]
fn test_parse_sshsig_blob_wrong_namespace() {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"SSHSIG");
    blob.extend_from_slice(&1u32.to_be_bytes());

    append_publickey(&mut blob, TEST_SSH_PUBKEY);
    blob.extend_from_slice(&encode_ssh_string(ATTESTATION_NAMESPACE.as_bytes()));

    let result = parse_sshsig_blob(&blob, KEY_PROTECTION_NAMESPACE, TEST_SSH_PUBKEY);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("namespace") || err_msg.contains("mismatch"));
}

#[test]
fn test_parse_sshsig_blob_non_empty_reserved() {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"SSHSIG");
    blob.extend_from_slice(&1u32.to_be_bytes());

    append_publickey(&mut blob, TEST_SSH_PUBKEY);
    blob.extend_from_slice(&encode_ssh_string(KEY_PROTECTION_NAMESPACE.as_bytes()));
    blob.extend_from_slice(&encode_ssh_string(b"not_empty")); // reserved must be empty!

    let result = parse_sshsig_blob(&blob, KEY_PROTECTION_NAMESPACE, TEST_SSH_PUBKEY);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("reserved") || err_msg.contains("empty"));
}

#[test]
fn test_parse_sshsig_blob_wrong_hashalg() {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"SSHSIG");
    blob.extend_from_slice(&1u32.to_be_bytes());

    append_publickey(&mut blob, TEST_SSH_PUBKEY);
    blob.extend_from_slice(&encode_ssh_string(KEY_PROTECTION_NAMESPACE.as_bytes()));
    blob.extend_from_slice(&encode_ssh_string(b""));
    blob.extend_from_slice(&encode_ssh_string(b"sha512")); // wrong hash algorithm!

    let result = parse_sshsig_blob(&blob, KEY_PROTECTION_NAMESPACE, TEST_SSH_PUBKEY);
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
    append_publickey(&mut blob, TEST_SSH_PUBKEY);
    blob.extend_from_slice(&encode_ssh_string(KEY_PROTECTION_NAMESPACE.as_bytes()));
    blob.extend_from_slice(&encode_ssh_string(b""));
    blob.extend_from_slice(&encode_ssh_string(b"sha256"));
    blob.extend_from_slice(&encode_ssh_string(b"test_signature_ikm"));

    let b64 = encode_base64_standard(&blob);
    let armored = format!(
        "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----",
        b64
    );

    let result = parse_sshsig_armored(&armored, KEY_PROTECTION_NAMESPACE, TEST_SSH_PUBKEY).unwrap();
    assert_eq!(result.as_bytes(), b"test_signature_ikm");
}

#[test]
fn test_parse_sshsig_armored_rejects_publickey_mismatch() {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"SSHSIG");
    blob.extend_from_slice(&1u32.to_be_bytes());
    append_publickey(&mut blob, OTHER_SSH_PUBKEY);
    blob.extend_from_slice(&encode_ssh_string(KEY_PROTECTION_NAMESPACE.as_bytes()));
    blob.extend_from_slice(&encode_ssh_string(b""));
    blob.extend_from_slice(&encode_ssh_string(b"sha256"));
    blob.extend_from_slice(&encode_ssh_string(b"test_signature_ikm"));

    let armored = format!(
        "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----",
        encode_base64_standard(&blob)
    );

    let result = parse_sshsig_armored(&armored, KEY_PROTECTION_NAMESPACE, TEST_SSH_PUBKEY);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("publickey"));
}

#[test]
fn test_parse_sshsig_armored_multiline_base64() {
    // Test with line-wrapped base64
    let mut blob = Vec::new();
    blob.extend_from_slice(b"SSHSIG");
    blob.extend_from_slice(&1u32.to_be_bytes());
    append_publickey(&mut blob, TEST_SSH_PUBKEY);
    blob.extend_from_slice(&encode_ssh_string(KEY_PROTECTION_NAMESPACE.as_bytes()));
    blob.extend_from_slice(&encode_ssh_string(b""));
    blob.extend_from_slice(&encode_ssh_string(b"sha256"));
    blob.extend_from_slice(&encode_ssh_string(b"multiline_test"));

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

    let result = parse_sshsig_armored(&armored, KEY_PROTECTION_NAMESPACE, TEST_SSH_PUBKEY).unwrap();
    assert_eq!(result.as_bytes(), b"multiline_test");
}

#[test]
fn test_parse_sshsig_armored_no_markers() {
    let result = parse_sshsig_armored(
        "just random text without markers",
        KEY_PROTECTION_NAMESPACE,
        TEST_SSH_PUBKEY,
    );
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
    let result = parse_sshsig_armored(armored, KEY_PROTECTION_NAMESPACE, TEST_SSH_PUBKEY);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("base64") || err_msg.contains("decode"));
}

#[test]
fn test_build_sshsig_signed_data_varies_by_namespace() {
    let message = b"namespace separation";
    let key_protection = build_sshsig_signed_data(message, KEY_PROTECTION_NAMESPACE);
    let attestation = build_sshsig_signed_data(message, ATTESTATION_NAMESPACE);

    assert_ne!(key_protection, attestation);
}

#[test]
fn test_parse_sshsig_blob_accepts_attestation_namespace_when_expected() {
    let mut blob = Vec::new();
    blob.extend_from_slice(SSHSIG_MAGIC);
    blob.extend_from_slice(&1u32.to_be_bytes());
    append_publickey(&mut blob, TEST_SSH_PUBKEY);
    blob.extend_from_slice(&encode_ssh_string(ATTESTATION_NAMESPACE.as_bytes()));
    blob.extend_from_slice(&encode_ssh_string(b""));
    blob.extend_from_slice(&encode_ssh_string(b"sha256"));
    blob.extend_from_slice(&encode_ssh_string(b"test_signature_ikm"));

    let signature = parse_sshsig_blob(&blob, ATTESTATION_NAMESPACE, TEST_SSH_PUBKEY).unwrap();
    assert_eq!(signature.as_bytes(), b"test_signature_ikm");
}

#[test]
fn test_sshsig_blob_debug_is_redacted() {
    let blob = SshsigBlob::new(vec![1u8; 8]);
    assert_eq!(format!("{:?}", blob), "SshsigBlob([REDACTED])");
}
