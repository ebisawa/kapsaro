// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for Trust Store format canonicalization

use secretenv::format::trust_store::build_trust_store_signature_bytes;
use secretenv::model::identifiers::format::TRUST_LOCAL_V4;
use secretenv::model::trust_store::{KnownKey, KnownKeyApprovalVia, TrustStoreProtected};
use std::collections::BTreeMap;

fn build_test_protected() -> TrustStoreProtected {
    TrustStoreProtected {
        format: TRUST_LOCAL_V4.to_string(),
        owner_handle: "alice@example.com".to_string(),
        created_at: "2026-03-29T12:34:56Z".to_string(),
        updated_at: "2026-03-29T12:34:56Z".to_string(),
        known_keys: vec![KnownKey {
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
            subject_handle: "bob@example.com".to_string(),
            approved_at: "2026-03-29T12:40:00Z".to_string(),
            approved_via: KnownKeyApprovalVia::ManualReview,
            evidence: None,
            extra: BTreeMap::new(),
        }],
        recipient_sets: Vec::new(),
    }
}

#[test]
fn test_trust_store_signature_bytes_deterministic() {
    let protected = build_test_protected();
    let bytes1 = build_trust_store_signature_bytes(&protected).unwrap();
    let bytes2 = build_trust_store_signature_bytes(&protected).unwrap();
    assert_eq!(bytes1, bytes2);
}

#[test]
fn test_trust_store_signature_bytes_non_empty() {
    let protected = build_test_protected();
    let bytes = build_trust_store_signature_bytes(&protected).unwrap();
    assert!(!bytes.is_empty());
}

#[test]
fn test_trust_store_signature_bytes_valid_json() {
    let protected = build_test_protected();
    let bytes = build_trust_store_signature_bytes(&protected).unwrap();
    let json_str = std::str::from_utf8(&bytes).unwrap();
    let _value: serde_json::Value = serde_json::from_str(json_str).unwrap();
}

#[test]
fn test_trust_store_signature_bytes_changes_with_content() {
    let protected1 = build_test_protected();
    let mut protected2 = build_test_protected();
    protected2.owner_handle = "charlie@example.com".to_string();

    let bytes1 = build_trust_store_signature_bytes(&protected1).unwrap();
    let bytes2 = build_trust_store_signature_bytes(&protected2).unwrap();
    assert_ne!(bytes1, bytes2);
}
