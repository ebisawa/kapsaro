// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/member_add module

use crate::test_utils::setup_test_workspace;
use kapsaro_core::cli_api::test_support::operations::member::add::add_member_from_file;
use kapsaro_core::cli_api::test_support::storage::workspace::members::load_incoming_member_files;
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

fn save_tampered_public_key(export_file: &std::path::Path, tamper: impl FnOnce(&mut Value)) {
    let mut value: Value = serde_json::from_str(&fs::read_to_string(export_file).unwrap()).unwrap();
    tamper(&mut value);
    fs::write(export_file, serde_json::to_string_pretty(&value).unwrap()).unwrap();
}

#[test]
fn test_add_member_valid_file() {
    // Create workspace with alice as active member
    let (_temp_dir, workspace_dir) = setup_test_workspace(&["alice@example.com"]);

    // Export alice's public key to a temp file
    let alice_key_path = workspace_dir.join("members/active/alice@example.com.json");
    let key_content = fs::read_to_string(&alice_key_path).unwrap();

    let export_dir = TempDir::new().unwrap();
    let export_file = export_dir.path().join("alice.json");
    fs::write(&export_file, &key_content).unwrap();

    // Create a fresh workspace with no members
    let temp_dir2 = TempDir::new().unwrap();
    let workspace_dir2 = temp_dir2.path().join("workspace");
    fs::create_dir_all(workspace_dir2.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir2.join("members/incoming")).unwrap();

    let member_handle = add_member_from_file(&workspace_dir2, &export_file, false).unwrap();
    assert_eq!(member_handle, "alice@example.com");

    let incoming = load_incoming_member_files(&workspace_dir2).unwrap();
    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].protected.subject_handle, "alice@example.com");
}

#[test]
fn test_add_member_invalid_json() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_dir = temp_dir.path().join("workspace");
    fs::create_dir_all(workspace_dir.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir.join("members/incoming")).unwrap();

    let export_dir = TempDir::new().unwrap();
    let export_file = export_dir.path().join("bad.json");
    fs::write(&export_file, "not json").unwrap();

    let result = add_member_from_file(&workspace_dir, &export_file, false);
    assert!(result.is_err());
}

#[test]
fn test_add_member_file_not_found() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_dir = temp_dir.path().join("workspace");
    fs::create_dir_all(workspace_dir.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir.join("members/incoming")).unwrap();

    let result = add_member_from_file(
        &workspace_dir,
        std::path::Path::new("/nonexistent/file.json"),
        false,
    );
    assert!(result.is_err());
}

#[test]
fn test_add_member_duplicate_without_force() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&["alice@example.com"]);

    let alice_key_path = workspace_dir.join("members/active/alice@example.com.json");
    let key_content = fs::read_to_string(&alice_key_path).unwrap();

    let export_dir = TempDir::new().unwrap();
    let export_file = export_dir.path().join("alice.json");
    fs::write(&export_file, &key_content).unwrap();

    // First add succeeds
    let temp_dir2 = TempDir::new().unwrap();
    let workspace_dir2 = temp_dir2.path().join("workspace");
    fs::create_dir_all(workspace_dir2.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir2.join("members/incoming")).unwrap();

    add_member_from_file(&workspace_dir2, &export_file, false).unwrap();

    // Second add without force fails
    let result = add_member_from_file(&workspace_dir2, &export_file, false);
    assert!(result.is_err());
}

#[test]
fn test_add_member_duplicate_with_force() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&["alice@example.com"]);

    let alice_key_path = workspace_dir.join("members/active/alice@example.com.json");
    let key_content = fs::read_to_string(&alice_key_path).unwrap();

    let export_dir = TempDir::new().unwrap();
    let export_file = export_dir.path().join("alice.json");
    fs::write(&export_file, &key_content).unwrap();

    let temp_dir2 = TempDir::new().unwrap();
    let workspace_dir2 = temp_dir2.path().join("workspace");
    fs::create_dir_all(workspace_dir2.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir2.join("members/incoming")).unwrap();

    add_member_from_file(&workspace_dir2, &export_file, false).unwrap();

    // Second add with force succeeds
    let result = add_member_from_file(&workspace_dir2, &export_file, true);
    assert!(result.is_ok());
}

#[test]
fn test_add_member_invalid_self_signature_error() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&["alice@example.com"]);

    let alice_key_path = workspace_dir.join("members/active/alice@example.com.json");
    let key_content = fs::read_to_string(&alice_key_path).unwrap();

    let export_dir = TempDir::new().unwrap();
    let export_file = export_dir.path().join("alice.json");
    fs::write(&export_file, &key_content).unwrap();
    save_tampered_public_key(&export_file, |value| {
        value["protected"]["expires_at"] = Value::String("2030-01-01T00:00:00Z".to_string());
    });

    let temp_dir2 = TempDir::new().unwrap();
    let workspace_dir2 = temp_dir2.path().join("workspace");
    fs::create_dir_all(workspace_dir2.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir2.join("members/incoming")).unwrap();

    let result = add_member_from_file(&workspace_dir2, &export_file, false);
    assert!(result.is_err());
}

#[test]
fn test_add_member_invalid_attestation_error() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&["alice@example.com"]);

    let alice_key_path = workspace_dir.join("members/active/alice@example.com.json");
    let key_content = fs::read_to_string(&alice_key_path).unwrap();

    let export_dir = TempDir::new().unwrap();
    let export_file = export_dir.path().join("alice.json");
    fs::write(&export_file, &key_content).unwrap();
    save_tampered_public_key(&export_file, |value| {
        value["protected"]["identity"]["attestation"]["pub"] =
            Value::String("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBroken broken@test".to_string());
    });

    let temp_dir2 = TempDir::new().unwrap();
    let workspace_dir2 = temp_dir2.path().join("workspace");
    fs::create_dir_all(workspace_dir2.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir2.join("members/incoming")).unwrap();

    let result = add_member_from_file(&workspace_dir2, &export_file, false);
    assert!(result.is_err());
}

#[cfg(unix)]
#[test]
fn test_add_member_rejects_symlink_input_file() {
    use std::os::unix::fs::symlink;

    let (_temp_dir, workspace_dir) = setup_test_workspace(&["alice@example.com"]);

    let alice_key_path = workspace_dir.join("members/active/alice@example.com.json");
    let export_dir = TempDir::new().unwrap();
    let export_file = export_dir.path().join("alice.json");
    symlink(&alice_key_path, &export_file).unwrap();

    let temp_dir2 = TempDir::new().unwrap();
    let workspace_dir2 = temp_dir2.path().join("workspace");
    fs::create_dir_all(workspace_dir2.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir2.join("members/incoming")).unwrap();

    let result = add_member_from_file(&workspace_dir2, &export_file, false);
    assert!(result.is_err());
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("symlink"),
        "unexpected error for symlink input: {message}"
    );
}
