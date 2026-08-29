// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for PublicKeySource trait implementations

use crate::app_test_utils::add_generated_key;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::keystore::public_key_source::{
    KeystorePublicKeySource, PublicKeySource, WorkspacePublicKeySource,
};
use crate::model::identity::{Kid, MemberHandle};
use crate::test_utils::{
    setup_test_keystore_from_fixtures, setup_test_workspace_from_fixtures, ALICE_MEMBER_HANDLE,
    BOB_MEMBER_HANDLE,
};
use std::fs;
use tempfile::TempDir;

fn build_test_public_key_json(member_handle: &str, kid: &str) -> String {
    format!(
        r#"{{
  "protected": {{
    "format": "kapsaro:format:public-key@1",
    "subject_handle": "{}",
    "kid": "{}",
  "keys": {{
    "kem": {{ "kty": "OKP", "crv": "X25519", "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }},
    "sig": {{ "kty": "OKP", "crv": "Ed25519", "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }}
  }},
  "attestation": {{
    "method": "ssh-sign",
    "pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
  }},
    "created_at": "2026-01-01T00:00:00Z",
    "expires_at": "2027-01-01T00:00:00Z"
  }},
  "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}}"#,
        member_handle, kid
    )
}

fn setup_workspace_member(workspace_path: &std::path::Path, member_handle: &str, kid: &str) {
    let active_dir = workspace_path.join("members/active");
    std::fs::create_dir_all(&active_dir).unwrap();
    let json = build_test_public_key_json(member_handle, kid);
    std::fs::write(active_dir.join(format!("{}.json", member_handle)), json).unwrap();
}

fn parse_member_handle(value: &str) -> MemberHandle {
    MemberHandle::try_from(value).unwrap()
}

/// Bulk resolution across multiple members must return one key per handle, in
/// the requested order, since the returned order drives which recipient gets
/// which wrapped key.
#[test]
fn test_keystore_public_key_source_load_public_keys_for_member_handles_multiple_members() {
    let (temp_dir, _workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let keystore_root = temp_dir.path().join("keys");
    let keystore_access = KeystoreAccess::open(keystore_root).unwrap();
    let source = KeystorePublicKeySource::new(keystore_access);
    let member_handles = vec![
        parse_member_handle(ALICE_MEMBER_HANDLE),
        parse_member_handle(BOB_MEMBER_HANDLE),
    ];

    let result = source
        .load_public_keys_for_member_handles(&member_handles)
        .unwrap();

    assert_eq!(result.len(), 2);
    assert_eq!(result[0].protected.subject_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(result[1].protected.subject_handle, BOB_MEMBER_HANDLE);
}

/// Without an `active` marker, resolution falls back to the most recently
/// created key rather than failing.
#[test]
fn test_keystore_public_key_source_load_public_keys_for_member_handles_without_active_kid() {
    let (temp_dir, _workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let keystore_root = temp_dir.path().join("keys");
    let keystore_access = KeystoreAccess::open(keystore_root).unwrap();
    let member_handle = parse_member_handle(ALICE_MEMBER_HANDLE);
    assert!(
        keystore_access
            .load_active_kid(&member_handle)
            .unwrap()
            .is_none(),
        "fixture must not set an active kid for this case"
    );
    let source = KeystorePublicKeySource::new(keystore_access);

    let result = source
        .load_public_keys_for_member_handles(&[member_handle])
        .unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].protected.subject_handle, ALICE_MEMBER_HANDLE);
}

/// When an `active` marker is present, resolution must use the kid it names.
#[test]
fn test_keystore_public_key_source_load_public_keys_for_member_handles_with_active_kid_set() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");
    let keystore_access = KeystoreAccess::open(keystore_root).unwrap();
    let member_handle = parse_member_handle(ALICE_MEMBER_HANDLE);
    let active_kid = keystore_access
        .load_active_kid(&member_handle)
        .unwrap()
        .expect("fixture must set an active kid for this case");
    let source = KeystorePublicKeySource::new(keystore_access);

    let result = source
        .load_public_keys_for_member_handles(&[member_handle])
        .unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].protected.subject_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(result[0].protected.kid, active_kid.as_str());
}

#[test]
fn test_workspace_public_key_source_load_public_key() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_path = temp_dir.path();

    let member_handle = "alice@example.com";
    let kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
    setup_workspace_member(workspace_path, member_handle, kid);

    let source = WorkspacePublicKeySource::new(workspace_path.to_path_buf());
    let result = source.load_public_key(&parse_member_handle(member_handle));
    assert!(result.is_ok(), "Expected Ok, got: {:?}", result);

    let public_key = result.unwrap();
    assert_eq!(public_key.protected.subject_handle, member_handle);
    assert_eq!(public_key.protected.kid, kid);
}

#[test]
fn test_workspace_public_key_source_load_not_found() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_path = temp_dir.path();
    std::fs::create_dir_all(workspace_path.join("members/active")).unwrap();

    let source = WorkspacePublicKeySource::new(workspace_path.to_path_buf());
    let result = source.load_public_key(&parse_member_handle("nonexistent@example.com"));
    assert!(result.is_err());
}

fn setup_incoming_member(workspace_path: &std::path::Path, member_handle: &str, kid: &str) {
    let incoming_dir = workspace_path.join("members/incoming");
    std::fs::create_dir_all(&incoming_dir).unwrap();
    let json = build_test_public_key_json(member_handle, kid);
    std::fs::write(incoming_dir.join(format!("{}.json", member_handle)), json).unwrap();
}

#[test]
fn test_workspace_public_key_source_rejects_incoming_member() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_path = temp_dir.path();

    // Only place member in incoming/ (not active/)
    std::fs::create_dir_all(workspace_path.join("members/active")).unwrap();
    setup_incoming_member(
        workspace_path,
        "pending@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE",
    );

    let source = WorkspacePublicKeySource::new(workspace_path.to_path_buf());
    let result = source.load_public_key(&parse_member_handle("pending@example.com"));
    assert!(result.is_err(), "Incoming member should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("not active"),
        "error should mention 'not active': {}",
        err
    );
}

#[test]
fn test_workspace_public_key_source_bulk_rejects_incoming_member() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_path = temp_dir.path();

    // Active member
    setup_workspace_member(
        workspace_path,
        "alice@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
    );
    // Incoming member
    setup_incoming_member(
        workspace_path,
        "pending@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE",
    );

    let source = WorkspacePublicKeySource::new(workspace_path.to_path_buf());
    let member_handles = vec![
        parse_member_handle("alice@example.com"),
        parse_member_handle("pending@example.com"),
    ];
    let result = source.load_public_keys_for_member_handles(&member_handles);
    assert!(
        result.is_err(),
        "Bulk load should reject when any member is not active"
    );
}

#[test]
fn test_workspace_public_key_source_load_multiple() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_path = temp_dir.path();

    let members = vec![
        ("alice@example.com", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
        ("bob@example.com", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE"),
        ("charlie@example.com", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GF"),
    ];

    for (member_handle, kid) in &members {
        setup_workspace_member(workspace_path, member_handle, kid);
    }

    let source = WorkspacePublicKeySource::new(workspace_path.to_path_buf());
    let member_handles: Vec<MemberHandle> = members
        .iter()
        .map(|(id, _)| parse_member_handle(id))
        .collect();
    let result = source.load_public_keys_for_member_handles(&member_handles);
    assert!(result.is_ok(), "Expected Ok, got: {:?}", result);

    let keys = result.unwrap();
    assert_eq!(keys.len(), 3);
    assert_eq!(keys[0].protected.subject_handle, "alice@example.com");
    assert_eq!(keys[1].protected.subject_handle, "bob@example.com");
    assert_eq!(keys[2].protected.subject_handle, "charlie@example.com");
}

#[test]
fn test_workspace_public_key_source_rejects_mismatched_active_file() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_path = temp_dir.path();

    setup_workspace_member(
        workspace_path,
        "alice@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
    );

    let tampered =
        build_test_public_key_json("bob@example.com", "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE");
    fs::write(
        workspace_path
            .join("members/active")
            .join("alice@example.com.json"),
        tampered,
    )
    .unwrap();

    let source = WorkspacePublicKeySource::new(workspace_path.to_path_buf());
    let result = source.load_public_key(&parse_member_handle("alice@example.com"));
    assert!(result.is_err(), "mismatched member file should be rejected");
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("Member handle mismatch"),
        "unexpected error: {message}"
    );
}

/// A workspace holds one key per member, so naming that key answers with it.
#[test]
fn test_workspace_public_key_source_load_public_key_for_kid() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_path = temp_dir.path();
    let member_handle = "alice@example.com";
    let kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
    setup_workspace_member(workspace_path, member_handle, kid);

    let source = WorkspacePublicKeySource::new(workspace_path.to_path_buf());
    let public_key = source
        .load_public_key_for_kid(
            &parse_member_handle(member_handle),
            &Kid::try_from(kid).unwrap(),
        )
        .unwrap();

    assert_eq!(public_key.protected.kid, kid);
}

/// Naming a key the workspace does not hold is refused rather than answered
/// with the key it does hold.
#[test]
fn test_workspace_public_key_source_rejects_other_kid() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_path = temp_dir.path();
    let member_handle = "alice@example.com";
    setup_workspace_member(
        workspace_path,
        member_handle,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
    );

    let source = WorkspacePublicKeySource::new(workspace_path.to_path_buf());
    let error = source
        .load_public_key_for_kid(
            &parse_member_handle(member_handle),
            &Kid::try_from("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE").unwrap(),
        )
        .unwrap_err();

    assert!(
        error.to_string().contains("was asked for"),
        "unexpected error: {error}"
    );
}

/// The keystore holds several keys per member, so naming a key that is not the
/// active one answers with that key rather than with the active one.
#[test]
fn test_keystore_public_key_source_load_public_key_for_kid() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");
    let spare_kid = add_generated_key(temp_dir.path(), ALICE_MEMBER_HANDLE);
    let keystore_access = KeystoreAccess::open(&keystore_root).unwrap();
    let member_handle = parse_member_handle(ALICE_MEMBER_HANDLE);
    let active_kid = keystore_access.resolve_kid(&member_handle, None).unwrap();
    assert_ne!(spare_kid, active_kid);
    let source = KeystorePublicKeySource::new(keystore_access);

    let public_key = source
        .load_public_key_for_kid(&member_handle, &spare_kid)
        .unwrap();

    assert_eq!(public_key.protected.kid, spare_kid.as_str());
    assert_eq!(public_key.protected.subject_handle, ALICE_MEMBER_HANDLE);
}
