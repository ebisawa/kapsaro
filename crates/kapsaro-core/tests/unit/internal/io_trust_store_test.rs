// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for trust store file I/O

use crate::io::trust::store::{
    load_trust_store_snapshot, save_trust_store_at, set_post_trust_store_save_hook,
    validate_trust_directory,
};
use crate::model::trust_store::{
    KnownKey, KnownKeyApprovalVia, KnownKeyEvidence, KnownKeyGithubAccount, TrustStoreDocument,
    TrustStoreProtected, TrustStoreSignature,
};
use crate::model::wire::format::LOCAL_TRUST_V1;
use crate::support::limits::MAX_JSON_DEPTH;
use crate::support::warning::LocalStateWarningGuard;
use crate::test_utils::{ensure_local_state_dir, local_state_temp_dir, save_local_state_file};
use std::collections::BTreeMap;
#[cfg(unix)]
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::{open_optional_child_dir, DirectoryScope, OpenDir};
use crate::test_support::storage::trust::store::save_trust_store;

fn open_trust_directory(base_dir: &Path) -> (AnchoredDir, OpenDir) {
    let base = AnchoredDir::open(
        base_dir,
        DirectoryScope::LocalState,
        "test local state root",
    )
    .unwrap();
    let trust_dir = open_optional_child_dir(&base, "trust")
        .unwrap()
        .expect("test trust directory must exist");
    (base, trust_dir)
}

fn build_test_document(owner: &str) -> TrustStoreDocument {
    TrustStoreDocument {
        protected: TrustStoreProtected {
            format: LOCAL_TRUST_V1.to_string(),
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
            sig: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                .to_string(),
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
    let dir = local_state_temp_dir();
    let trust_dir = dir.path().join("trust");
    ensure_local_state_dir(&trust_dir);
    let path = trust_dir.join("nonexistent.json");
    let (base, opened_trust_dir) = open_trust_directory(dir.path());
    let result = load_trust_store_snapshot(&base, &opened_trust_dir, &path).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_save_and_load_trust_store_roundtrip() {
    let dir = local_state_temp_dir();
    let trust_dir = dir.path().join("trust");
    let path = trust_dir.join("alice@example.com.json");

    let doc = build_test_document("alice@example.com");
    save_trust_store(&path, &doc).unwrap();

    let (base, opened_trust_dir) = open_trust_directory(dir.path());
    let loaded = load_trust_store_snapshot(&base, &opened_trust_dir, &path)
        .unwrap()
        .unwrap();
    assert_eq!(loaded.document, doc);
}

#[test]
fn test_validate_trust_directory_ignores_unrelated_entries() {
    let dir = local_state_temp_dir();
    std::fs::write(dir.path().join(".DS_Store"), "metadata").unwrap();
    std::fs::create_dir(dir.path().join("unrelated-directory")).unwrap();
    let anchored = AnchoredDir::open(
        dir.path(),
        DirectoryScope::LocalState,
        "test trust directory",
    )
    .unwrap();

    validate_trust_directory(&anchored).unwrap();
}

#[test]
fn test_validate_trust_directory_rejects_canonical_name_with_wrong_type() {
    let dir = local_state_temp_dir();
    std::fs::create_dir(dir.path().join("alice@example.com.json")).unwrap();
    let anchored = AnchoredDir::open(
        dir.path(),
        DirectoryScope::LocalState,
        "test trust directory",
    )
    .unwrap();

    let error = validate_trust_directory(&anchored).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
}

/// A symlink wearing a trust store's own name would stand in for the document
/// the loader looks up, so it is refused just as a directory of that name is.
#[cfg(unix)]
#[test]
fn test_validate_trust_directory_rejects_symlink_under_a_trust_store_name() {
    let dir = local_state_temp_dir();
    let trust_dir = dir.path().join("trust");
    let outside = dir.path().join("outside.json");
    ensure_local_state_dir(&trust_dir);
    std::fs::write(&outside, "outside").unwrap();
    symlink(&outside, trust_dir.join("unrelated.json")).unwrap();
    let anchored = AnchoredDir::open(
        &trust_dir,
        DirectoryScope::LocalState,
        "test trust directory",
    )
    .unwrap();

    let error = validate_trust_directory(&anchored).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
}

/// Under any other name a symlink names no trust store, so it is left alone the
/// way an unrelated regular file is.
#[cfg(unix)]
#[test]
fn test_validate_trust_directory_allows_symlink_outside_trust_store_names() {
    let dir = local_state_temp_dir();
    let trust_dir = dir.path().join("trust");
    let outside = dir.path().join("outside.txt");
    ensure_local_state_dir(&trust_dir);
    std::fs::write(&outside, "outside").unwrap();
    symlink(&outside, trust_dir.join("notes.txt")).unwrap();
    let anchored = AnchoredDir::open(
        &trust_dir,
        DirectoryScope::LocalState,
        "test trust directory",
    )
    .unwrap();

    validate_trust_directory(&anchored).unwrap();
}

/// Internal staging names are ignored by normal trust readers.
#[test]
fn test_validate_trust_directory_ignores_leftover_staging_entry() {
    let dir = local_state_temp_dir();
    let trust_dir = dir.path().join("trust");
    ensure_local_state_dir(&trust_dir);
    std::fs::write(
        trust_dir.join(".alice@example.com.json.tmp.3f2504e0-4f89-41d3-9a0c-0305e82c3301"),
        "staged",
    )
    .unwrap();
    let anchored = AnchoredDir::open(
        &trust_dir,
        DirectoryScope::LocalState,
        "test trust directory",
    )
    .unwrap();

    validate_trust_directory(&anchored).unwrap();
}

#[test]
fn test_save_trust_store_creates_parent_directory() {
    let dir = local_state_temp_dir();
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

    let dir = local_state_temp_dir();
    let path = dir.path().join("trust").join("alice@example.com.json");

    save_trust_store(&path, &build_test_document("alice@example.com")).unwrap();

    let metadata = std::fs::metadata(&path).unwrap();
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn test_load_trust_store_filename_mismatch_fails() {
    let dir = local_state_temp_dir();
    let trust_dir = dir.path().join("trust");
    let path = trust_dir.join("wrong_name.json");
    ensure_local_state_dir(&trust_dir);

    let doc = build_test_document("alice@example.com");
    let json = serde_json::to_string_pretty(&doc).unwrap();
    save_local_state_file(&path, json);

    let (base, opened_trust_dir) = open_trust_directory(dir.path());
    let result = load_trust_store_snapshot(&base, &opened_trust_dir, &path);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("FILENAME_MISMATCH") || err_msg.contains("does not match"));
}

#[test]
fn test_load_trust_store_invalid_json_fails() {
    let dir = local_state_temp_dir();
    let trust_dir = dir.path().join("trust");
    let path = trust_dir.join("alice@example.com.json");
    ensure_local_state_dir(&trust_dir);

    save_local_state_file(&path, "not valid json");

    let (base, opened_trust_dir) = open_trust_directory(dir.path());
    let result = load_trust_store_snapshot(&base, &opened_trust_dir, &path);
    assert!(result.is_err());
}

#[test]
fn test_load_trust_store_rejects_duplicate_top_level_member() {
    let dir = local_state_temp_dir();
    let trust_dir = dir.path().join("trust");
    let path = trust_dir.join("alice@example.com.json");
    ensure_local_state_dir(&trust_dir);
    let duplicate_signature = r#"{
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
            "sig": "first_signature"
        },
        "signature": {
            "alg": "eddsa-ed25519",
            "kid": "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D",
            "sig": "second_signature"
        }
    }"#;
    save_local_state_file(&path, duplicate_signature);

    let (base, opened_trust_dir) = open_trust_directory(dir.path());
    let result = load_trust_store_snapshot(&base, &opened_trust_dir, &path);

    assert!(result.is_err());
    let error = result.unwrap_err();
    let message = error.format_user_message();
    assert!(message.contains("duplicate JSON member name"));
    assert!(message.contains("signature"));
}

#[test]
fn test_load_trust_store_rejects_duplicate_nested_member() {
    let dir = local_state_temp_dir();
    let trust_dir = dir.path().join("trust");
    let path = trust_dir.join("alice@example.com.json");
    ensure_local_state_dir(&trust_dir);
    let duplicate_owner = r#"{
        "protected": {
            "format": "kapsaro:format:local-trust@1",
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
    save_local_state_file(&path, duplicate_owner);

    let (base, opened_trust_dir) = open_trust_directory(dir.path());
    let result = load_trust_store_snapshot(&base, &opened_trust_dir, &path);

    assert!(result.is_err());
    let error = result.unwrap_err();
    let message = error.format_user_message();
    assert!(message.contains("duplicate JSON member name"));
    assert!(message.contains("owner_handle"));
}

#[test]
fn test_load_trust_store_rejects_json_exceeding_depth_limit_before_parse() {
    let dir = local_state_temp_dir();
    let base_dir = dir.path().join("kapsaro");
    let trust_dir = base_dir.join("trust");
    let path = trust_dir.join("alice@example.com.json");
    ensure_local_state_dir(&trust_dir);
    save_local_state_file(&path, deeply_nested_json(MAX_JSON_DEPTH + 1));

    let (base, opened_trust_dir) = open_trust_directory(&base_dir);
    let result = load_trust_store_snapshot(&base, &opened_trust_dir, &path);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("nesting depth exceeds limit"));
}

#[cfg(unix)]
#[test]
fn test_load_trust_store_warns_about_insecure_parent_directory_permissions() {
    let dir = local_state_temp_dir();
    let base_dir = dir.path().join("kapsaro");
    let trust_dir = base_dir.join("trust");
    let path = trust_dir.join("alice@example.com.json");
    std::fs::create_dir_all(&trust_dir).unwrap();
    std::fs::set_permissions(&base_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&trust_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    let doc = build_test_document("alice@example.com");
    let json = serde_json::to_string_pretty(&doc).unwrap();
    std::fs::write(&path, json).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let (base, opened_trust_dir) = open_trust_directory(&base_dir);

    let guard = LocalStateWarningGuard::new();
    let loaded = load_trust_store_snapshot(&base, &opened_trust_dir, &path)
        .unwrap()
        .unwrap();
    let warnings = guard.take_reasons();

    assert_eq!(loaded.document, doc);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("expected 0700"), "{warnings:?}");
    assert!(warnings[0].contains("chmod 0700"), "{warnings:?}");
}

#[test]
fn test_load_trust_store_rejects_oversized_document_before_parse() {
    use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;

    let dir = local_state_temp_dir();
    let base_dir = dir.path().join("kapsaro");
    let trust_dir = base_dir.join("trust");
    let path = trust_dir.join("alice@example.com.json");
    ensure_local_state_dir(&trust_dir);
    save_local_state_file(&path, vec![b'A'; MAX_JSON_DOCUMENT_READ_SIZE + 1]);

    let (base, opened_trust_dir) = open_trust_directory(&base_dir);
    let result = load_trust_store_snapshot(&base, &opened_trust_dir, &path);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("exceeds maximum size limit"));
}

/// The directory the approvals land in is inspected on the way in, the way the
/// read path inspects it before handing a store back. The write goes ahead, so
/// the operator gets the approval they asked for and is told at once that the
/// directory holding it is open to others.
#[cfg(unix)]
#[test]
fn test_save_trust_store_at_reports_a_trust_directory_open_to_others() {
    let dir = local_state_temp_dir();
    let base_dir = dir.path().join("kapsaro");
    let trust_dir = base_dir.join("trust");
    std::fs::create_dir_all(&trust_dir).unwrap();
    std::fs::set_permissions(&base_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&trust_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = trust_dir.join("alice@example.com.json");
    let document = build_test_document("alice@example.com");
    let (base, opened_trust_dir) = open_trust_directory(&base_dir);

    let guard = LocalStateWarningGuard::new();
    crate::support::fs::lock::with_exclusive_locked_directory(&opened_trust_dir, |locked| {
        save_trust_store_at(&base, locked, &path, &document)
    })
    .unwrap();
    let warnings = guard.take_reasons();

    assert!(path.exists(), "the document must land");
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("expected 0700"), "{warnings:?}");
}

#[cfg(unix)]
#[test]
fn test_save_trust_store_at_reports_a_completed_write_when_the_directory_turns_unsafe() {
    let dir = local_state_temp_dir();
    let trust_dir = dir.path().join("trust");
    let outside = dir.path().join("outside.json");
    ensure_local_state_dir(&trust_dir);
    std::fs::write(&outside, "outside").unwrap();
    let path = trust_dir.join("alice@example.com.json");
    let document = build_test_document("alice@example.com");

    let planted = trust_dir.join("planted.json");
    set_post_trust_store_save_hook(move || symlink(&outside, &planted).unwrap());

    let (base, opened_trust_dir) = open_trust_directory(dir.path());
    let error =
        crate::support::fs::lock::with_exclusive_locked_directory(&opened_trust_dir, |locked| {
            save_trust_store_at(&base, locked, &path, &document)
        })
        .expect_err("a trust directory that turns unsafe after the write must be reported");

    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
    let message = error.format_user_message();
    assert!(message.contains("was written"), "unexpected: {message}");
    assert!(path.exists(), "the document must stay on disk");
}
