// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for FileEncDocument model

use crate::model::file_enc::{
    FileEncAlgorithm, FileEncDocument, FileEncDocumentProtected, FilePayload,
    FilePayloadCiphertext, FilePayloadHeader,
};
use crate::model::signature::ArtifactSignature;
use crate::model::wire::algorithm;
use crate::test_utils::keygen_helpers::{build_dummy_key_possession_proof, build_dummy_public_key};
use uuid::Uuid;

fn build_test_payload_envelope() -> FilePayload {
    let sid = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
    FilePayload {
        protected: FilePayloadHeader {
            format: crate::model::wire::format::FILE_PAYLOAD_V1.to_string(),
            sid,
            alg: FileEncAlgorithm {
                aead: crate::model::wire::algorithm::AEAD_XCHACHA20_POLY1305.to_string(),
            },
        },
        encrypted: FilePayloadCiphertext {
            nonce: "nonce_base64url".to_string(),
            ct: "ciphertext_base64url".to_string(),
        },
    }
}

#[test]
fn test_file_enc_document_basic() {
    let sid = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
    let doc = FileEncDocument {
        protected: FileEncDocumentProtected {
            format: crate::model::wire::format::FILE_ENC_V1.to_string(),
            sid,
            wrap: vec![crate::model::common::WrapItem {
                recipient_handle: "alice@example.com".to_string(),
                kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
                alg: algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305.to_string(),
                enc: "enc_base64url".to_string(),
                ct: "ct_base64url".to_string(),
            }],
            removed_recipients: None,
            payload: build_test_payload_envelope(),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            updated_at: "2025-01-01T00:00:00Z".to_string(),
        },
        signature: ArtifactSignature {
            alg: crate::model::wire::algorithm::SIGNATURE_ED25519.to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
            signer_pub: build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
            mac: build_dummy_key_possession_proof(),
            sig: "signature_base64url".to_string(),
        },
    };

    let json = serde_json::to_string(&doc).unwrap();
    let deserialized: FileEncDocument = serde_json::from_str(&json).unwrap();
    assert_eq!(doc, deserialized);
}

#[test]
fn test_recipients_derived_from_wrap() {
    let sid = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
    let doc = FileEncDocument {
        protected: FileEncDocumentProtected {
            format: crate::model::wire::format::FILE_ENC_V1.to_string(),
            sid,
            wrap: vec![
                crate::model::common::WrapItem {
                    recipient_handle: "alice@example.com".to_string(),
                    kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
                    alg: algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305.to_string(),
                    enc: "enc1".to_string(),
                    ct: "ct1".to_string(),
                },
                crate::model::common::WrapItem {
                    recipient_handle: "bob@example.com".to_string(),
                    kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GH".to_string(),
                    alg: algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305.to_string(),
                    enc: "enc2".to_string(),
                    ct: "ct2".to_string(),
                },
            ],
            removed_recipients: None,
            payload: build_test_payload_envelope(),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            updated_at: "2025-01-01T00:00:00Z".to_string(),
        },
        signature: ArtifactSignature {
            alg: crate::model::wire::algorithm::SIGNATURE_ED25519.to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
            signer_pub: build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
            mac: build_dummy_key_possession_proof(),
            sig: "sig".to_string(),
        },
    };

    let recipients = doc.recipients();
    assert_eq!(recipients.len(), 2);
    assert_eq!(recipients[0], "alice@example.com");
    assert_eq!(recipients[1], "bob@example.com");
}

#[test]
fn test_payload_serialization() {
    // Test that payload.protected correctly serializes without sid field
    let sid = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
    let doc = FileEncDocument {
        protected: FileEncDocumentProtected {
            format: crate::model::wire::format::FILE_ENC_V1.to_string(),
            sid,
            wrap: vec![],
            removed_recipients: None,
            payload: build_test_payload_envelope(),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            updated_at: "2025-01-01T00:00:00Z".to_string(),
        },
        signature: ArtifactSignature {
            alg: crate::model::wire::algorithm::SIGNATURE_ED25519.to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
            signer_pub: build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
            mac: build_dummy_key_possession_proof(),
            sig: "sig".to_string(),
        },
    };

    let json = serde_json::to_string_pretty(&doc).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Verify outer protected has sid
    assert_eq!(parsed["protected"]["sid"], sid.to_string());

    // Verify payload.protected has sid (must match outer sid)
    assert_eq!(
        parsed["protected"]["payload"]["protected"]["sid"],
        sid.to_string()
    );

    // Verify payload.protected has format and alg
    assert_eq!(
        parsed["protected"]["payload"]["protected"]["format"],
        "kapsaro:format:file-enc:payload@1"
    );
    assert_eq!(
        parsed["protected"]["payload"]["protected"]["alg"]["aead"],
        "xchacha20-poly1305"
    );
}

#[test]
fn test_file_enc_document_signature_requires_signer_pub() {
    let json = serde_json::json!({
        "protected": {
            "format": crate::model::wire::format::FILE_ENC_V1,
            "sid": "01234567-89ab-cdef-0123-456789abcdef",
            "wrap": [],
            "payload": {
                "protected": {
                    "format": crate::model::wire::format::FILE_PAYLOAD_V1,
                    "sid": "01234567-89ab-cdef-0123-456789abcdef",
                    "alg": {
                        "aead": crate::model::wire::algorithm::AEAD_XCHACHA20_POLY1305
                    }
                },
                "encrypted": {
                    "nonce": "nonce_base64url",
                    "ct": "ciphertext_base64url"
                }
            },
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-01T00:00:00Z"
        },
        "signature": {
            "alg": crate::model::wire::algorithm::SIGNATURE_ED25519,
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "sig": "signature_base64url"
        }
    });

    let result = serde_json::from_value::<FileEncDocument>(json);
    assert!(result.is_err());
}
