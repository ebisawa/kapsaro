// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for Trust Store JSON Schema validation

use crate::test_utils::ALICE_MEMBER_HANDLE;
use crate::test_utils::{setup_member_key_context, setup_test_keystore_from_fixtures};
use secretenv::feature::trust::signature::sign_trust_store;
use secretenv::feature::trust::verification::verify_trust_store;
use secretenv::format::schema::validator::load_embedded_trust_validator;
use secretenv::model::identifiers::format::TRUST_LOCAL_V3;
use secretenv::model::trust_store::{KnownKey, KnownKeyApprovalVia, TrustStoreProtected};
use std::collections::BTreeMap;

#[test]
fn test_trust_store_schema_valid_document() {
    let doc: serde_json::Value = serde_json::from_str(
        r#"{
            "protected": {
                "format": "secretenv.trust.local@3",
                "owner_handle": "alice@example.com",
                "created_at": "2026-03-29T12:34:56Z",
                "updated_at": "2026-03-29T12:34:56Z",
                "known_keys": [
                    {
                        "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
                        "subject_handle": "bob@example.com",
                        "approved_at": "2026-03-29T12:40:00Z",
                        "approved_via": "manual-review",
                        "evidence": {
                            "github_account": {
                                "id": 12345678,
                                "login": "bob-gh"
                            },
                            "ssh_attestor_pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."
                        }
                    }
                ]
            },
            "signature": {
                "alg": "eddsa-ed25519",
                "kid": "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D",
                "sig": "test_signature"
            }
        }"#,
    )
    .unwrap();

    let validator = load_embedded_trust_validator().unwrap();
    validator.validate_trust_store(&doc).unwrap();
}

#[test]
fn test_trust_store_schema_rejects_signer_pub() {
    let doc: serde_json::Value = serde_json::from_str(
        r#"{
            "protected": {
                "format": "secretenv.trust.local@3",
                "owner_handle": "alice@example.com",
                "created_at": "2026-03-29T12:34:56Z",
                "updated_at": "2026-03-29T12:34:56Z",
                "known_keys": []
            },
            "signature": {
                "alg": "eddsa-ed25519",
                "kid": "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D",
                "signer_pub": { "test": true },
                "sig": "test_signature"
            }
        }"#,
    )
    .unwrap();

    let validator = load_embedded_trust_validator().unwrap();
    let error = validator.validate_trust_store(&doc).unwrap_err();
    let message = error.format_user_message();
    assert!(message.contains("Invalid secretenv document"));
    assert!(message.contains("signature"));
    assert!(message.contains("signer_pub"));
    assert!(!message.contains("E_SCHEMA_INVALID"));
    assert!(!message.contains("schema"));
}

#[test]
fn test_trust_store_schema_accepts_github_account_without_login() {
    let doc: serde_json::Value = serde_json::from_str(
        r#"{
            "protected": {
                "format": "secretenv.trust.local@3",
                "owner_handle": "alice@example.com",
                "created_at": "2026-03-29T12:34:56Z",
                "updated_at": "2026-03-29T12:34:56Z",
                "known_keys": [
                    {
                        "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
                        "subject_handle": "bob@example.com",
                        "approved_at": "2026-03-29T12:40:00Z",
                        "approved_via": "manual-review",
                        "evidence": {
                            "github_account": {
                                "id": 12345678
                            }
                        }
                    }
                ]
            },
            "signature": {
                "alg": "eddsa-ed25519",
                "kid": "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D",
                "sig": "test_signature"
            }
        }"#,
    )
    .unwrap();

    let validator = load_embedded_trust_validator().unwrap();
    validator.validate_trust_store(&doc).unwrap();
}

#[test]
fn test_trust_store_schema_empty_known_keys() {
    let doc: serde_json::Value = serde_json::from_str(
        r#"{
            "protected": {
                "format": "secretenv.trust.local@3",
                "owner_handle": "alice@example.com",
                "created_at": "2026-03-29T12:34:56Z",
                "updated_at": "2026-03-29T12:34:56Z",
                "known_keys": []
            },
            "signature": {
                "alg": "eddsa-ed25519",
                "kid": "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D",
                "sig": "test_signature"
            }
        }"#,
    )
    .unwrap();

    let validator = load_embedded_trust_validator().unwrap();
    validator.validate_trust_store(&doc).unwrap();
}

#[test]
fn test_trust_store_schema_missing_required_field_fails() {
    let doc: serde_json::Value = serde_json::from_str(
        r#"{
            "protected": {
                "format": "secretenv.trust.local@3",
                "owner_handle": "alice@example.com",
                "created_at": "2026-03-29T12:34:56Z",
                "known_keys": []
            },
            "signature": {
                "alg": "eddsa-ed25519",
                "kid": "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D",
                "sig": "test_signature"
            }
        }"#,
    )
    .unwrap();

    let validator = load_embedded_trust_validator().unwrap();
    let error = validator.validate_trust_store(&doc).unwrap_err();
    let message = error.format_user_message();
    assert!(message.contains("Invalid secretenv document"));
    assert!(message.contains("protected"));
    assert!(message.contains("updated_at"));
    assert!(!message.contains("E_SCHEMA_INVALID"));
    assert!(!message.contains("schema"));
}

#[test]
fn test_trust_store_schema_invalid_timestamp_fails() {
    let doc: serde_json::Value = serde_json::from_str(
        r#"{
            "protected": {
                "format": "secretenv.trust.local@3",
                "owner_handle": "alice@example.com",
                "created_at": "2026-03-29 12:34:56",
                "updated_at": "2026-03-29T12:34:56Z",
                "known_keys": []
            },
            "signature": {
                "alg": "eddsa-ed25519",
                "kid": "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D",
                "sig": "test_signature"
            }
        }"#,
    )
    .unwrap();

    let validator = load_embedded_trust_validator().unwrap();
    let error = validator.validate_trust_store(&doc).unwrap_err();
    let message = error.format_user_message();
    assert!(message.contains("Invalid secretenv document"));
    assert!(message.contains("protected.created_at"));
    assert!(message.contains("does not match"));
    assert!(!message.contains("2026-03-29 12:34:56"));
    assert!(!message.contains("E_SCHEMA_INVALID"));
    assert!(!message.contains("schema"));
}

#[test]
fn test_trust_store_schema_non_utc_timestamp_fails() {
    let doc: serde_json::Value = serde_json::from_str(
        r#"{
            "protected": {
                "format": "secretenv.trust.local@3",
                "owner_handle": "alice@example.com",
                "created_at": "2026-03-29T12:34:56+09:00",
                "updated_at": "2026-03-29T12:34:56Z",
                "known_keys": []
            },
            "signature": {
                "alg": "eddsa-ed25519",
                "kid": "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D",
                "sig": "test_signature"
            }
        }"#,
    )
    .unwrap();

    let validator = load_embedded_trust_validator().unwrap();
    let error = validator.validate_trust_store(&doc).unwrap_err();
    let message = error.format_user_message();
    assert!(message.contains("Invalid secretenv document"));
    assert!(message.contains("protected.created_at"));
    assert!(message.contains("does not match"));
    assert!(!message.contains("2026-03-29T12:34:56+09:00"));
    assert!(!message.contains("E_SCHEMA_INVALID"));
    assert!(!message.contains("schema"));
}

#[test]
fn test_trust_store_schema_known_key_allows_extra_fields() {
    let doc: serde_json::Value = serde_json::from_str(
        r#"{
            "protected": {
                "format": "secretenv.trust.local@3",
                "owner_handle": "alice@example.com",
                "created_at": "2026-03-29T12:34:56Z",
                "updated_at": "2026-03-29T12:34:56Z",
                "known_keys": [
                    {
                        "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
                        "subject_handle": "bob@example.com",
                        "approved_at": "2026-03-29T12:40:00Z",
                        "approved_via": "manual-review",
                        "future_metadata": { "key": "value" }
                    }
                ]
            },
            "signature": {
                "alg": "eddsa-ed25519",
                "kid": "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D",
                "sig": "test_signature"
            }
        }"#,
    )
    .unwrap();

    let validator = load_embedded_trust_validator().unwrap();
    validator.validate_trust_store(&doc).unwrap();
}

#[test]
fn test_trust_store_schema_rejects_extra_top_level_fields() {
    let doc: serde_json::Value = serde_json::from_str(
        r#"{
            "protected": {
                "format": "secretenv.trust.local@3",
                "owner_handle": "alice@example.com",
                "created_at": "2026-03-29T12:34:56Z",
                "updated_at": "2026-03-29T12:34:56Z",
                "known_keys": []
            },
            "signature": {
                "alg": "eddsa-ed25519",
                "kid": "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D",
                "sig": "test_signature"
            },
            "unexpected": true
        }"#,
    )
    .unwrap();

    let validator = load_embedded_trust_validator().unwrap();
    assert!(validator.validate_trust_store(&doc).is_err());
}

#[test]
fn test_verify_trust_store_rejects_semantically_invalid_timestamp() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let key_ctx = setup_member_key_context(&home, ALICE_MEMBER_HANDLE, None);
    let protected = TrustStoreProtected {
        format: TRUST_LOCAL_V3.to_string(),
        owner_handle: ALICE_MEMBER_HANDLE.to_string(),
        created_at: "2026-03-29T12:34:56Z".to_string(),
        updated_at: "2026-03-29T12:34:56Z".to_string(),
        known_keys: vec![KnownKey {
            kid: "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0".to_string(),
            subject_handle: "bob@example.com".to_string(),
            approved_at: "2026-02-30T12:00:00Z".to_string(),
            approved_via: KnownKeyApprovalVia::ManualReview,
            evidence: None,
            extra: BTreeMap::new(),
        }],
    };
    let doc = sign_trust_store(&protected, &key_ctx.signing_key, &key_ctx.kid).unwrap();

    let result = verify_trust_store(&doc, &home.path().join("keys"));

    assert!(result.is_err());
}
