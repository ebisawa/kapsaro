// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for SSH protocol types

use kapsaro_core::cli_api::test_support::storage::ssh::protocol::types::{
    Ed25519RawSignature, SshSignatureBlob,
};
use kapsaro_core::cli_api::test_support::storage::ssh::protocol::wire::encode_ssh_string;
use zeroize::Zeroizing;

#[test]
fn test_ed25519_raw_signature_from_slice() {
    let mut bytes = [0u8; 64];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    let sig = Ed25519RawSignature::from_slice(&bytes).unwrap();
    assert_eq!(sig.as_bytes(), &bytes);
}

#[test]
fn test_ed25519_raw_signature_invalid_length() {
    let bytes = vec![0u8; 63];
    assert!(Ed25519RawSignature::from_slice(&bytes).is_err());
}

#[test]
fn test_ed25519_raw_signature_debug_is_redacted() {
    let sig = Ed25519RawSignature::new([7u8; 64]);
    assert_eq!(format!("{:?}", sig), "Ed25519RawSignature([REDACTED])");
}

#[test]
fn test_ed25519_raw_signature_to_vec_returns_zeroizing_bytes() {
    let sig = Ed25519RawSignature::new([9u8; 64]);
    let bytes = sig.to_vec();
    assert_eq!(bytes.len(), 64);
    assert!(bytes.iter().all(|byte| *byte == 9));
}

#[test]
fn test_ssh_signature_blob_extract_from_raw_64() {
    let mut raw = [0u8; 64];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(3).wrapping_add(1);
    }
    let blob = SshSignatureBlob::new(raw.to_vec());
    let extracted = blob.extract_ed25519_raw().unwrap();
    assert_eq!(extracted.as_bytes(), &raw);
}

#[test]
fn test_ssh_signature_blob_extract_from_wire_format() {
    let mut sig64 = [0u8; 64];
    for (i, b) in sig64.iter_mut().enumerate() {
        *b = (255u8).wrapping_sub(i as u8);
    }

    let mut blob_bytes = Vec::new();
    blob_bytes.extend_from_slice(&encode_ssh_string(
        kapsaro_core::cli_api::test_support::storage::ssh::protocol::constants::KEY_TYPE_ED25519
            .as_bytes(),
    ));
    blob_bytes.extend_from_slice(&encode_ssh_string(&sig64));

    let blob = SshSignatureBlob::new(blob_bytes);
    let extracted = blob.extract_ed25519_raw().unwrap();
    assert_eq!(extracted.as_bytes(), &sig64);
}

#[test]
fn test_ssh_signature_blob_from_zeroizing_preserves_bytes() {
    let blob = SshSignatureBlob::from_zeroizing(Zeroizing::new(vec![1, 2, 3]));

    assert_eq!(blob.as_bytes(), &[1, 2, 3]);
}

#[test]
fn test_ssh_signature_blob_rejects_algo_mismatch() {
    let mut sig64 = [0u8; 64];
    sig64.fill(7);

    let mut blob_bytes = Vec::new();
    blob_bytes.extend_from_slice(&encode_ssh_string(b"ssh-rsa"));
    blob_bytes.extend_from_slice(&encode_ssh_string(&sig64));

    let blob = SshSignatureBlob::new(blob_bytes);
    let err = blob.extract_ed25519_raw().unwrap_err().to_string();
    assert!(err.contains("Unsupported"));
}

#[test]
fn test_ssh_signature_blob_rejects_truncated_algorithm_string() {
    let blob = SshSignatureBlob::new(vec![0, 0, 0, 11, b's', b's', b'h']);

    let err = blob.extract_ed25519_raw().unwrap_err().to_string();

    assert!(err.contains("Expected"));
}

#[test]
fn test_ssh_signature_blob_rejects_truncated_signature_string() {
    let mut blob_bytes = Vec::new();
    blob_bytes.extend_from_slice(&encode_ssh_string(
        kapsaro_core::cli_api::test_support::storage::ssh::protocol::constants::KEY_TYPE_ED25519
            .as_bytes(),
    ));
    blob_bytes.extend_from_slice(&64u32.to_be_bytes());
    blob_bytes.extend_from_slice(&[1, 2, 3]);

    let blob = SshSignatureBlob::new(blob_bytes);
    let err = blob.extract_ed25519_raw().unwrap_err().to_string();

    assert!(err.contains("Expected"));
}

#[test]
fn test_ssh_signature_blob_rejects_wrong_sig_length() {
    let sig = vec![1u8; 63];
    let mut blob_bytes = Vec::new();
    blob_bytes.extend_from_slice(&encode_ssh_string(
        kapsaro_core::cli_api::test_support::storage::ssh::protocol::constants::KEY_TYPE_ED25519
            .as_bytes(),
    ));
    blob_bytes.extend_from_slice(&encode_ssh_string(&sig));

    let blob = SshSignatureBlob::new(blob_bytes);
    let err = blob.extract_ed25519_raw().unwrap_err().to_string();
    assert!(err.contains("expected 64"));
}

#[test]
fn test_ssh_signature_blob_rejects_trailing_data() {
    let mut blob_bytes = Vec::new();
    blob_bytes.extend_from_slice(&encode_ssh_string(
        kapsaro_core::cli_api::test_support::storage::ssh::protocol::constants::KEY_TYPE_ED25519
            .as_bytes(),
    ));
    blob_bytes.extend_from_slice(&encode_ssh_string(&[3u8; 64]));
    blob_bytes.push(0);

    let blob = SshSignatureBlob::new(blob_bytes);
    let err = blob.extract_ed25519_raw().unwrap_err().to_string();

    assert!(err.contains("trailing bytes"), "unexpected: {err}");
}

#[test]
fn test_ssh_signature_blob_debug_is_redacted() {
    let blob = SshSignatureBlob::new(vec![1u8; 8]);
    assert_eq!(format!("{:?}", blob), "SshSignatureBlob([REDACTED])");
}
