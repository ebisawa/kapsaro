// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for Trust Store JSON Schema validation

use crate::test_utils::ALICE_MEMBER_HANDLE;
use crate::test_utils::{setup_member_key_context, setup_test_keystore_from_fixtures};
use kapsaro_core::cli_api::test_support::domain::trust_store::{
    KnownKey, KnownKeyApprovalVia, RecipientSetApprovalVia, RecipientSetRecord, TrustStoreProtected,
};
use kapsaro_core::cli_api::test_support::domain::wire::format::LOCAL_TRUST_V1;
use kapsaro_core::cli_api::test_support::operations::trust::recipient_sets::compute_recipient_set_hash;
use kapsaro_core::cli_api::test_support::operations::trust::signature::sign_trust_store;
use kapsaro_core::cli_api::test_support::operations::trust::verification::verify_trust_store;
use kapsaro_core::cli_api::test_support::wire::schema::validator::load_embedded_trust_validator;
use std::collections::BTreeMap;

const BOB_KID: &str = "KBD2AAAA1111BBBB2222CCCC3333DDDD";
const CAROL_KID: &str = "KCD3AAAA1111BBBB2222CCCC3333DDDD";

fn known_key(kid: &str, subject_handle: &str) -> KnownKey {
    KnownKey {
        kid: kid.to_string(),
        subject_handle: subject_handle.to_string(),
        approved_at: "2026-03-29T12:40:00Z".to_string(),
        approved_via: KnownKeyApprovalVia::ManualReview,
        evidence: None,
        extra: BTreeMap::new(),
    }
}

fn recipient_set_record(sid: &str, kids: &[&str]) -> RecipientSetRecord {
    let recipient_kids = kids
        .iter()
        .map(|kid| (*kid).to_string())
        .collect::<Vec<_>>();
    RecipientSetRecord {
        sid: sid.to_string(),
        recipient_set_hash: compute_recipient_set_hash(&recipient_kids).unwrap(),
        recipient_kids,
        approved_at: "2026-03-29T12:40:00Z".to_string(),
        approved_via: RecipientSetApprovalVia::ManualReview,
        recipient_handle_hints: None,
    }
}

#[test]
fn test_trust_store_schema_valid_document() {
    let doc: serde_json::Value = serde_json::from_str(
        r#"{
            "protected": {
                "format": "kapsaro:format:local-trust@1",
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
                ],
                "recipient_sets": []
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
                "format": "kapsaro:format:local-trust@1",
                "owner_handle": "alice@example.com",
                "created_at": "2026-03-29T12:34:56Z",
                "updated_at": "2026-03-29T12:34:56Z",
                "known_keys": [],
                "recipient_sets": []
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
    assert!(message.contains("Invalid kapsaro document"));
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
                "format": "kapsaro:format:local-trust@1",
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
                ],
                "recipient_sets": []
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
                "format": "kapsaro:format:local-trust@1",
                "owner_handle": "alice@example.com",
                "created_at": "2026-03-29T12:34:56Z",
                "updated_at": "2026-03-29T12:34:56Z",
                "known_keys": [],
                "recipient_sets": []
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
                "format": "kapsaro:format:local-trust@1",
                "owner_handle": "alice@example.com",
                "created_at": "2026-03-29T12:34:56Z",
                "known_keys": [],
                "recipient_sets": []
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
    assert!(message.contains("Invalid kapsaro document"));
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
                "format": "kapsaro:format:local-trust@1",
                "owner_handle": "alice@example.com",
                "created_at": "2026-03-29 12:34:56",
                "updated_at": "2026-03-29T12:34:56Z",
                "known_keys": [],
                "recipient_sets": []
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
    assert!(message.contains("Invalid kapsaro document"));
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
                "format": "kapsaro:format:local-trust@1",
                "owner_handle": "alice@example.com",
                "created_at": "2026-03-29T12:34:56+09:00",
                "updated_at": "2026-03-29T12:34:56Z",
                "known_keys": [],
                "recipient_sets": []
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
    assert!(message.contains("Invalid kapsaro document"));
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
                "format": "kapsaro:format:local-trust@1",
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
                ],
                "recipient_sets": []
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
                "format": "kapsaro:format:local-trust@1",
                "owner_handle": "alice@example.com",
                "created_at": "2026-03-29T12:34:56Z",
                "updated_at": "2026-03-29T12:34:56Z",
                "known_keys": [],
                "recipient_sets": []
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
        format: LOCAL_TRUST_V1.to_string(),
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
        recipient_sets: Vec::new(),
    };
    let doc = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();

    let result = verify_trust_store(&doc, &home.path().join("keys"));

    assert!(result.is_err());
}

#[test]
fn test_verify_trust_store_rejects_duplicate_known_key_kid() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let key_ctx = setup_member_key_context(&home, ALICE_MEMBER_HANDLE, None);
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: ALICE_MEMBER_HANDLE.to_string(),
        created_at: "2026-03-29T12:34:56Z".to_string(),
        updated_at: "2026-03-29T12:34:56Z".to_string(),
        known_keys: vec![
            known_key(BOB_KID, "bob@example.com"),
            known_key(BOB_KID, "bob-alt@example.com"),
        ],
        recipient_sets: Vec::new(),
    };
    let doc = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();

    let result = verify_trust_store(&doc, &home.path().join("keys"));

    let error = result.expect_err("duplicate kid must fail");
    assert_eq!(error.kind(), kapsaro_core::ErrorKind::Verify);
    assert_eq!(error.verification_rule(), Some("E_TRUST_DUPLICATE_KID"));
}

#[test]
fn test_verify_trust_store_rejects_duplicate_recipient_set_sid() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let key_ctx = setup_member_key_context(&home, ALICE_MEMBER_HANDLE, None);
    let sid = "00000000-0000-0000-0000-000000000001";
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: ALICE_MEMBER_HANDLE.to_string(),
        created_at: "2026-03-29T12:34:56Z".to_string(),
        updated_at: "2026-03-29T12:34:56Z".to_string(),
        known_keys: Vec::new(),
        recipient_sets: vec![
            recipient_set_record(sid, &[BOB_KID]),
            recipient_set_record(sid, &[CAROL_KID]),
        ],
    };
    let doc = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();

    let result = verify_trust_store(&doc, &home.path().join("keys"));

    let error = result.expect_err("duplicate recipient set sid must fail");
    assert_eq!(error.kind(), kapsaro_core::ErrorKind::Verify);
    assert_eq!(
        error.verification_rule(),
        Some("E_RECIPIENT_SET_DUPLICATE_SID")
    );
}
