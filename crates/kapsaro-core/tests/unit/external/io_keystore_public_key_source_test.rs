// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for PublicKeySource trait implementations

use kapsaro_core::cli_api::test_support::storage::keystore::public_key_source::{
    PublicKeySource, WorkspacePublicKeySource,
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

#[test]
fn test_workspace_public_key_source_load_public_key() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_path = temp_dir.path();

    let member_handle = "alice@example.com";
    let kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
    setup_workspace_member(workspace_path, member_handle, kid);

    let source = WorkspacePublicKeySource::new(workspace_path.to_path_buf());
    let result = source.load_public_key(member_handle);
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
    let result = source.load_public_key("nonexistent@example.com");
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
    let result = source.load_public_key("pending@example.com");
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
        "alice@example.com".to_string(),
        "pending@example.com".to_string(),
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
    let member_handles: Vec<String> = members.iter().map(|(id, _)| id.to_string()).collect();
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
    let result = source.load_public_key("alice@example.com");
    assert!(result.is_err(), "mismatched member file should be rejected");
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("Member handle mismatch"),
        "unexpected error: {message}"
    );
}
