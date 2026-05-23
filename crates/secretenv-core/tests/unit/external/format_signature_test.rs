// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for file-enc canonicalization

use ed25519_dalek::SigningKey;
use secretenv_core::cli_api::test_support::domain::common::WrapItem;
use secretenv_core::cli_api::test_support::domain::file_enc::{
    FileEncAlgorithm, FileEncDocumentProtected, FilePayload, FilePayloadCiphertext,
    FilePayloadHeader,
};
use secretenv_core::cli_api::test_support::domain::wire::algorithm;
use secretenv_core::cli_api::test_support::operations::envelope::signature::{
    sign_file_document, verify_file_signature,
};
use secretenv_core::cli_api::test_support::primitives::types::keys::MasterKey;
use secretenv_core::cli_api::test_support::wire::file::build_file_signature_bytes;
use uuid::Uuid;

use crate::keygen_helpers::build_dummy_public_key;

fn build_test_file_enc_document_protected() -> FileEncDocumentProtected {
    let sid = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
    FileEncDocumentProtected {
        format: secretenv_core::cli_api::test_support::domain::wire::format::FILE_ENC_V6.to_string(),
        sid,
        wrap: vec![WrapItem {
            recipient_handle: "alice@example.com".to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
            alg: algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305.to_string(),
            enc: "enc_base64url".to_string(),
            ct: "ct_base64url".to_string(),
        }],
        removed_recipients: None,
        payload: FilePayload {
            protected: FilePayloadHeader {
                format: secretenv_core::cli_api::test_support::domain::wire::format::FILE_PAYLOAD_V6.to_string(),
                sid,
                alg: FileEncAlgorithm {
                    aead: secretenv_core::cli_api::test_support::domain::wire::algorithm::AEAD_XCHACHA20_POLY1305
                        .to_string(),
                },
            },
            encrypted: FilePayloadCiphertext {
                nonce: "nonce_base64url".to_string(),
                ct: "ciphertext_base64url".to_string(),
            },
        },
        created_at: "2025-01-01T00:00:00Z".to_string(),
        updated_at: "2025-01-01T00:00:00Z".to_string(),
    }
}

#[test]
fn test_build_canonical_bytes_file_deterministic() {
    let doc = build_test_file_enc_document_protected();

    let bytes1 = build_file_signature_bytes(&doc).unwrap();
    let bytes2 = build_file_signature_bytes(&doc).unwrap();

    // JCS normalization should be deterministic
    assert_eq!(bytes1, bytes2);
}

#[test]
fn test_sign_file_document_returns_valid_structure() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let content_key = MasterKey::new([7u8; 32]);

    let doc = build_test_file_enc_document_protected();

    let sig = sign_file_document(
        &doc,
        &content_key,
        &sk,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
        false,
    )
    .unwrap();

    assert_eq!(
        sig.alg,
        secretenv_core::cli_api::test_support::domain::wire::algorithm::SIGNATURE_ED25519
    );
    assert_eq!(sig.kid, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD");
    assert_eq!(sig.signer_pub.protected.subject_handle, "signer@test");
    assert_eq!(sig.mac.algorithm().as_wire_prefix(), "hmac-sha256");
    assert!(!sig.sig.is_empty());
}

#[test]
fn test_verify_file_enc_signature_accepts_valid_signature() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    let content_key = MasterKey::new([7u8; 32]);

    let doc = build_test_file_enc_document_protected();

    let sig = sign_file_document(
        &doc,
        &content_key,
        &sk,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
        false,
    )
    .unwrap();
    verify_file_signature(&doc, &vk, &sig, false).unwrap();
}

#[test]
fn test_verify_file_enc_signature_rejects_tampered_document() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    let content_key = MasterKey::new([7u8; 32]);

    let doc = build_test_file_enc_document_protected();

    let sig = sign_file_document(
        &doc,
        &content_key,
        &sk,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
        false,
    )
    .unwrap();

    // Tamper document
    let mut tampered = doc.clone();
    tampered.updated_at = "2025-01-01T00:00:01Z".to_string();

    let result = verify_file_signature(&tampered, &vk, &sig, false);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Signature verification failed"));
}

#[test]
fn test_sign_file_document_deterministic() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let content_key = MasterKey::new([7u8; 32]);

    let doc = build_test_file_enc_document_protected();

    let sig1 = sign_file_document(
        &doc,
        &content_key,
        &sk,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
        false,
    )
    .unwrap();
    let sig2 = sign_file_document(
        &doc,
        &content_key,
        &sk,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
        false,
    )
    .unwrap();

    // Ed25519 signatures are deterministic per RFC 8032
    assert_eq!(sig1.sig, sig2.sig);
}
