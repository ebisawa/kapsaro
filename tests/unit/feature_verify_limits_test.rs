// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::keygen_helpers::make_dummy_public_key;
use secretenv::feature::verify::file::verify_file_document;
use secretenv::feature::verify::kv::signature::verify_kv_document;
use secretenv::model::common::WrapItem;
use secretenv::model::file_enc::{
    FileEncAlgorithm, FileEncDocument, FileEncDocumentProtected, FilePayload,
    FilePayloadCiphertext, FilePayloadHeader,
};
use secretenv::model::identifiers::{alg, format, hpke};
use secretenv::model::kv_enc::document::KvEncDocument;
use secretenv::model::kv_enc::header::{KvHeader, KvWrap};
use secretenv::model::signature::ArtifactSignature;
use secretenv::support::limits::MAX_WRAP_ITEMS;
use uuid::Uuid;

fn test_wrap_item() -> WrapItem {
    WrapItem {
        rid: "alice@example.com".to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        alg: hpke::ALG_HPKE_32_1_3.to_string(),
        enc: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        ct: "AAAAAAAAAAAAAAAA".to_string(),
    }
}

#[test]
fn test_verify_file_document_rejects_wrap_count_over_limit() {
    let sid = Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap();
    let doc = FileEncDocument {
        protected: FileEncDocumentProtected {
            format: format::FILE_ENC_V3.to_string(),
            sid,
            wrap: vec![test_wrap_item(); MAX_WRAP_ITEMS + 1],
            removed_recipients: None,
            payload: FilePayload {
                protected: FilePayloadHeader {
                    format: format::FILE_PAYLOAD_V3.to_string(),
                    sid,
                    alg: FileEncAlgorithm {
                        aead: alg::AEAD_XCHACHA20_POLY1305.to_string(),
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
            alg: alg::SIGNATURE_ED25519.to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
            signer_pub: make_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
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
        ":SECRETENV_KV 3\n".to_string(),
        Vec::new(),
        KvHeader {
            sid: Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap(),
            created_at: "2026-01-14T00:00:00Z".to_string(),
            updated_at: "2026-01-14T00:00:00Z".to_string(),
        },
        KvWrap {
            wrap: vec![test_wrap_item(); MAX_WRAP_ITEMS + 1],
            removed_recipients: None,
        },
        "invalid".to_string(),
    );

    let result = verify_kv_document(&doc, false);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("wrap count"));
}
