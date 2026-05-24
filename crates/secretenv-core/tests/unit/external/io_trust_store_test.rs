// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for trust store file I/O

use secretenv_core::cli_api::test_support::domain::trust_store::{
    KnownKey, KnownKeyApprovalVia, KnownKeyEvidence, KnownKeyGithubAccount, TrustStoreDocument,
    TrustStoreProtected, TrustStoreSignature,
};
use secretenv_core::cli_api::test_support::domain::wire::format::LOCAL_TRUST_V5;
use secretenv_core::cli_api::test_support::helpers::limits::MAX_JSON_DEPTH;
use secretenv_core::cli_api::test_support::storage::trust::store::{
    load_trust_store, save_trust_store,
};
use std::collections::BTreeMap;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

fn build_test_document(owner: &str) -> TrustStoreDocument {
    TrustStoreDocument {
        protected: TrustStoreProtected {
            format: LOCAL_TRUST_V5.to_string(),
            owner_handle: owner.to_string(),
            created_at: "2026-03-29T12:34:56Z".to_string(),
            updated_at: "2026-03-29T12:34:56Z".to_string(),
            known_keys: vec![KnownKey {
                kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
                subject_handle: "bob@example.com".to_string(),
                approved_at: "2026-03-29T12:40:00Z".to_string(),
                approved_via: KnownKeyApprovalVia::ManualReview,
                evidence: Some(KnownKeyEvidence {
                    github_account: Some(KnownKeyGithubAccount {
                        id: 12345678,
                        login: Some("bob-gh".to_string()),
                    }),
                    ssh_attestor_pub: None,
                }),
                extra: BTreeMap::new(),
            }],
            recipient_sets: Vec::new(),
        },
        signature: TrustStoreSignature {
            alg: "eddsa-ed25519".to_string(),
            kid: "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D".to_string(),
            sig: "test_signature".to_string(),
        },
    }
}

fn deeply_nested_json(depth: usize) -> String {
    let mut json = String::new();
    for _ in 0..depth {
        json.push_str(r#"{"nested":"#);
    }
    json.push_str(r#""value""#);
    for _ in 0..depth {
        json.push('}');
    }
    json
}

#[test]
fn test_load_trust_store_nonexistent_returns_none() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("nonexistent.json");
    let result = load_trust_store(&path, dir.path()).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_save_and_load_trust_store_roundtrip() {
    let dir = TempDir::new().unwrap();
    let trust_dir = dir.path().join("trust");
    let path = trust_dir.join("alice@example.com.json");

    let doc = build_test_document("alice@example.com");
    save_trust_store(&path, &doc).unwrap();

    let loaded = load_trust_store(&path, dir.path()).unwrap().unwrap();
    assert_eq!(loaded.document, doc);
}

#[test]
fn test_save_trust_store_creates_parent_directory() {
    let dir = TempDir::new().unwrap();
    let trust_dir = dir.path().join("trust");
    let path = trust_dir.join("alice@example.com.json");

    assert!(!trust_dir.exists());
    save_trust_store(&path, &build_test_document("alice@example.com")).unwrap();
    assert!(trust_dir.exists());
}

#[cfg(unix)]
#[test]
fn test_save_trust_store_file_permission_0600() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("alice@example.com.json");

    save_trust_store(&path, &build_test_document("alice@example.com")).unwrap();

    let metadata = std::fs::metadata(&path).unwrap();
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn test_load_trust_store_filename_mismatch_fails() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("wrong_name.json");

    let doc = build_test_document("alice@example.com");
    let json = serde_json::to_string_pretty(&doc).unwrap();
    std::fs::write(&path, json).unwrap();

    let result = load_trust_store(&path, dir.path());
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("FILENAME_MISMATCH") || err_msg.contains("does not match"));
}

#[test]
fn test_load_trust_store_invalid_json_fails() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("alice@example.com.json");

    std::fs::write(&path, "not valid json").unwrap();

    let result = load_trust_store(&path, dir.path());
    assert!(result.is_err());
}

#[test]
fn test_load_trust_store_rejects_duplicate_top_level_member() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("alice@example.com.json");
    let duplicate_signature = r#"{
        "protected": {
            "format": "secretenv:format:local-trust@5",
            "owner_handle": "alice@example.com",
            "created_at": "2026-03-29T12:34:56Z",
            "updated_at": "2026-03-29T12:34:56Z",
            "known_keys": [],
            "recipient_sets": []
        },
        "signature": {
            "alg": "eddsa-ed25519",
            "kid": "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D",
            "sig": "first_signature"
        },
        "signature": {
            "alg": "eddsa-ed25519",
            "kid": "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D",
            "sig": "second_signature"
        }
    }"#;
    std::fs::write(&path, duplicate_signature).unwrap();

    let result = load_trust_store(&path, dir.path());

    assert!(result.is_err());
    let error = result.unwrap_err();
    let message = error.format_user_message();
    assert!(message.contains("duplicate JSON member name"));
    assert!(message.contains("signature"));
}

#[test]
fn test_load_trust_store_rejects_duplicate_nested_member() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("alice@example.com.json");
    let duplicate_owner = r#"{
        "protected": {
            "format": "secretenv:format:local-trust@5",
            "owner_handle": "mallory@example.com",
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
    }"#;
    std::fs::write(&path, duplicate_owner).unwrap();

    let result = load_trust_store(&path, dir.path());

    assert!(result.is_err());
    let error = result.unwrap_err();
    let message = error.format_user_message();
    assert!(message.contains("duplicate JSON member name"));
    assert!(message.contains("owner_handle"));
}

#[test]
fn test_load_trust_store_rejects_json_exceeding_depth_limit_before_parse() {
    let dir = TempDir::new().unwrap();
    let base_dir = dir.path().join("secretenv");
    let trust_dir = base_dir.join("trust");
    let path = trust_dir.join("alice@example.com.json");
    std::fs::create_dir_all(&trust_dir).unwrap();
    std::fs::write(&path, deeply_nested_json(MAX_JSON_DEPTH + 1)).unwrap();

    let result = load_trust_store(&path, &base_dir);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("nesting depth exceeds limit"));
}

#[cfg(unix)]
#[test]
fn test_load_trust_store_warns_on_insecure_parent_directory_permissions() {
    let dir = TempDir::new().unwrap();
    let base_dir = dir.path().join("secretenv");
    let trust_dir = base_dir.join("trust");
    let path = trust_dir.join("alice@example.com.json");
    std::fs::create_dir_all(&trust_dir).unwrap();
    std::fs::set_permissions(&base_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&trust_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    let doc = build_test_document("alice@example.com");
    let json = serde_json::to_string_pretty(&doc).unwrap();
    std::fs::write(&path, json).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let loaded = load_trust_store(&path, &base_dir).unwrap().unwrap();

    assert_eq!(loaded.permission_warnings.len(), 1);
    assert!(loaded.permission_warnings[0].contains("expected 0700"));
}

#[test]
fn test_load_trust_store_rejects_oversized_document_before_parse() {
    use secretenv_core::cli_api::test_support::helpers::limits::MAX_JSON_DOCUMENT_READ_SIZE;

    let dir = TempDir::new().unwrap();
    let base_dir = dir.path().join("secretenv");
    let trust_dir = base_dir.join("trust");
    let path = trust_dir.join("alice@example.com.json");
    std::fs::create_dir_all(&trust_dir).unwrap();
    std::fs::write(&path, vec![b'A'; MAX_JSON_DOCUMENT_READ_SIZE + 1]).unwrap();

    let result = load_trust_store(&path, &base_dir);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("exceeds maximum size limit"));
}
