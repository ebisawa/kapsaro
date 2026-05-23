// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for TrustStoreDocument model

use secretenv_core::cli_api::test_support::domain::trust_store::{
    KnownKey, KnownKeyApprovalVia, KnownKeyEvidence, KnownKeyGithubAccount, TrustStoreDocument,
    TrustStoreProtected, TrustStoreSignature,
};
use secretenv_core::cli_api::test_support::domain::wire::format::LOCAL_TRUST_V5;
use std::collections::BTreeMap;

fn build_test_known_key(kid: &str, member_handle: &str) -> KnownKey {
    KnownKey {
        kid: kid.to_string(),
        subject_handle: member_handle.to_string(),
        approved_at: "2026-03-29T12:40:00Z".to_string(),
        approved_via: KnownKeyApprovalVia::ManualReview,
        evidence: None,
        extra: BTreeMap::new(),
    }
}

fn build_test_document() -> TrustStoreDocument {
    TrustStoreDocument {
        protected: TrustStoreProtected {
            format: LOCAL_TRUST_V5.to_string(),
            owner_handle: "alice@example.com".to_string(),
            created_at: "2026-03-29T12:34:56Z".to_string(),
            updated_at: "2026-03-29T12:34:56Z".to_string(),
            known_keys: vec![build_test_known_key(
                "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
                "bob@example.com",
            )],
            recipient_sets: Vec::new(),
        },
        signature: TrustStoreSignature {
            alg: "eddsa-ed25519".to_string(),
            kid: "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D".to_string(),
            sig: "signature_base64url".to_string(),
        },
    }
}

#[test]
fn test_trust_store_serialize_deserialize_roundtrip() {
    let doc = build_test_document();
    let json = serde_json::to_string_pretty(&doc).unwrap();
    let deserialized: TrustStoreDocument = serde_json::from_str(&json).unwrap();
    assert_eq!(doc, deserialized);
}

#[test]
fn test_trust_store_format_identifier() {
    let doc = build_test_document();
    assert_eq!(doc.protected.format, LOCAL_TRUST_V5);
}

#[test]
fn test_known_key_with_evidence_roundtrip() {
    let key = KnownKey {
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        subject_handle: "bob@example.com".to_string(),
        approved_at: "2026-03-29T12:40:00Z".to_string(),
        approved_via: KnownKeyApprovalVia::ManualReview,
        evidence: Some(KnownKeyEvidence {
            github_account: Some(KnownKeyGithubAccount {
                id: 12345678,
                login: Some("bob-gh".to_string()),
            }),
            ssh_attestor_pub: Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...".to_string()),
        }),
        extra: BTreeMap::new(),
    };

    let json = serde_json::to_string(&key).unwrap();
    let deserialized: KnownKey = serde_json::from_str(&json).unwrap();
    assert_eq!(key, deserialized);
}

#[test]
fn test_known_key_with_github_id_only_roundtrip() {
    let json = serde_json::json!({
        "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        "subject_handle": "bob@example.com",
        "approved_at": "2026-03-29T12:40:00Z",
        "approved_via": "manual-review",
        "evidence": {
            "github_account": {
                "id": 12345678
            }
        }
    });

    let key: KnownKey = serde_json::from_value(json).unwrap();
    let serialized = serde_json::to_value(&key).unwrap();
    assert_eq!(
        serialized["evidence"]["github_account"]["id"],
        serde_json::json!(12345678)
    );
    assert!(serialized["evidence"]["github_account"]
        .as_object()
        .unwrap()
        .get("login")
        .is_none());
}

#[test]
fn test_known_key_unknown_fields_forward_compatible() {
    let json = r#"{
        "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        "subject_handle": "bob@example.com",
        "approved_at": "2026-03-29T12:40:00Z",
        "approved_via": "manual-review",
        "future_field": "some_value",
        "another_future": 42
    }"#;

    let key: KnownKey = serde_json::from_str(json).unwrap();
    assert_eq!(key.kid, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD");
    assert_eq!(key.extra.len(), 2);
    assert_eq!(
        key.extra.get("future_field").unwrap(),
        &serde_json::Value::String("some_value".to_string())
    );

    // Roundtrip preserves unknown fields
    let re_json = serde_json::to_string(&key).unwrap();
    let re_key: KnownKey = serde_json::from_str(&re_json).unwrap();
    assert_eq!(key, re_key);
}

#[test]
fn test_trust_store_empty_known_keys() {
    let doc = TrustStoreDocument {
        protected: TrustStoreProtected {
            format: LOCAL_TRUST_V5.to_string(),
            owner_handle: "alice@example.com".to_string(),
            created_at: "2026-03-29T12:34:56Z".to_string(),
            updated_at: "2026-03-29T12:34:56Z".to_string(),
            known_keys: vec![],
            recipient_sets: Vec::new(),
        },
        signature: TrustStoreSignature {
            alg: "eddsa-ed25519".to_string(),
            kid: "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D".to_string(),
            sig: "signature_base64url".to_string(),
        },
    };

    let json = serde_json::to_string(&doc).unwrap();
    let deserialized: TrustStoreDocument = serde_json::from_str(&json).unwrap();
    assert_eq!(doc, deserialized);
    assert!(deserialized.protected.known_keys.is_empty());
}

#[test]
fn test_trust_store_protected_rejects_unknown_fields() {
    let json = r#"{
        "protected": {
            "format": "secretenv:format:local-trust@5",
            "owner_handle": "alice@example.com",
            "created_at": "2026-03-29T12:34:56Z",
            "updated_at": "2026-03-29T12:34:56Z",
            "known_keys": [],
            "unexpected_field": true
        },
        "signature": {
            "alg": "eddsa-ed25519",
            "kid": "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D",
            "sig": "test"
        }
    }"#;

    let result = serde_json::from_str::<TrustStoreDocument>(json);
    assert!(result.is_err());
}
