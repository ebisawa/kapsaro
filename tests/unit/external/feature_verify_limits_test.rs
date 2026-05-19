// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::keygen_helpers::{build_dummy_key_possession_proof, build_dummy_public_key};
use secretenv_core::cli_api::test_support::domain::common::WrapItem;
use secretenv_core::cli_api::test_support::domain::file_enc::{
    FileEncAlgorithm, FileEncDocument, FileEncDocumentProtected, FilePayload,
    FilePayloadCiphertext, FilePayloadHeader,
};
use secretenv_core::cli_api::test_support::domain::kv_enc::document::KvEncDocument;
use secretenv_core::cli_api::test_support::domain::kv_enc::header::{
    KvFileAlgorithm, KvHeader, KvWrap,
};
use secretenv_core::cli_api::test_support::domain::signature::ArtifactSignature;
use secretenv_core::cli_api::test_support::domain::wire::{algorithm, format};
use secretenv_core::cli_api::test_support::helpers::limits::MAX_WRAP_ITEMS;
use secretenv_core::cli_api::test_support::operations::verify::file::verify_file_document;
use secretenv_core::cli_api::test_support::operations::verify::kv::signature::verify_kv_document;
use uuid::Uuid;

fn test_wrap_item() -> WrapItem {
    WrapItem {
        recipient_handle: "alice@example.com".to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        alg: algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305.to_string(),
        enc: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        ct: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    }
}

fn test_wrap_item_with(recipient_handle: &str, kid: &str) -> WrapItem {
    WrapItem {
        recipient_handle: recipient_handle.to_string(),
        kid: kid.to_string(),
        alg: algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305.to_string(),
        enc: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        ct: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    }
}

fn test_signature() -> ArtifactSignature {
    ArtifactSignature {
        alg: algorithm::SIGNATURE_ED25519.to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        signer_pub: build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
        mac: build_dummy_key_possession_proof(),
        sig: "invalid".to_string(),
    }
}

#[test]
fn test_verify_file_document_rejects_wrap_count_over_limit() {
    let sid = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap();
    let doc = FileEncDocument {
        protected: FileEncDocumentProtected {
            format: format::FILE_ENC_V6.to_string(),
            sid,
            wrap: vec![test_wrap_item(); MAX_WRAP_ITEMS + 1],
            removed_recipients: None,
            payload: FilePayload {
                protected: FilePayloadHeader {
                    format: format::FILE_PAYLOAD_V6.to_string(),
                    sid,
                    alg: FileEncAlgorithm {
                        aead: algorithm::AEAD_XCHACHA20_POLY1305.to_string(),
                    },
                },
                encrypted: FilePayloadCiphertext {
                    nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    ct: "AAAAAAAAAAAAAAAA".to_string(),
                },
            },
            created_at: "2026-01-14T00:00:00Z".to_string(),
            updated_at: "2026-01-14T00:00:00Z".to_string(),
        },
        signature: ArtifactSignature {
            alg: algorithm::SIGNATURE_ED25519.to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
            signer_pub: build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
            mac: build_dummy_key_possession_proof(),
            sig: "invalid".to_string(),
        },
    };

    let result = verify_file_document(&doc, false);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("wrap count"));
}

#[test]
fn test_verify_kv_document_rejects_wrap_count_over_limit() {
    let doc = KvEncDocument::new(
        ":SECRETENV_KV 8\n".to_string(),
        Vec::new(),
        KvHeader {
            sid: Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap(),
            alg: KvFileAlgorithm {
                aead: algorithm::AEAD_XCHACHA20_POLY1305.to_string(),
            },
            created_at: "2026-01-14T00:00:00Z".to_string(),
            updated_at: "2026-01-14T00:00:00Z".to_string(),
        },
        KvWrap {
            wrap: vec![test_wrap_item(); MAX_WRAP_ITEMS + 1],
            removed_recipients: None,
        },
        Vec::new(),
        "invalid".to_string(),
        test_signature(),
    );

    let result = verify_kv_document(&doc, false);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("wrap count"));
}

#[test]
fn test_verify_file_document_rejects_duplicate_wrap_rh() {
    let sid = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap();
    let doc = FileEncDocument {
        protected: FileEncDocumentProtected {
            format: format::FILE_ENC_V6.to_string(),
            sid,
            wrap: vec![
                test_wrap_item_with("alice@example.com", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
                test_wrap_item_with("alice@example.com", "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D"),
            ],
            removed_recipients: None,
            payload: FilePayload {
                protected: FilePayloadHeader {
                    format: format::FILE_PAYLOAD_V6.to_string(),
                    sid,
                    alg: FileEncAlgorithm {
                        aead: algorithm::AEAD_XCHACHA20_POLY1305.to_string(),
                    },
                },
                encrypted: FilePayloadCiphertext {
                    nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    ct: "AAAAAAAAAAAAAAAA".to_string(),
                },
            },
            created_at: "2026-01-14T00:00:00Z".to_string(),
            updated_at: "2026-01-14T00:00:00Z".to_string(),
        },
        signature: ArtifactSignature {
            alg: algorithm::SIGNATURE_ED25519.to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
            signer_pub: build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
            mac: build_dummy_key_possession_proof(),
            sig: "invalid".to_string(),
        },
    };

    let result = verify_file_document(&doc, false);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("E_DUPLICATE_RECIPIENT_HANDLE"));
}

#[test]
fn test_verify_kv_document_rejects_duplicate_wrap_rh() {
    let doc = KvEncDocument::new(
        ":SECRETENV_KV 8\n".to_string(),
        Vec::new(),
        KvHeader {
            sid: Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap(),
            alg: KvFileAlgorithm {
                aead: algorithm::AEAD_XCHACHA20_POLY1305.to_string(),
            },
            created_at: "2026-01-14T00:00:00Z".to_string(),
            updated_at: "2026-01-14T00:00:00Z".to_string(),
        },
        KvWrap {
            wrap: vec![
                test_wrap_item_with("alice@example.com", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
                test_wrap_item_with("alice@example.com", "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D"),
            ],
            removed_recipients: None,
        },
        Vec::new(),
        "invalid".to_string(),
        test_signature(),
    );

    let result = verify_kv_document(&doc, false);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("E_DUPLICATE_RECIPIENT_HANDLE"));
}
