// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/init module

use crate::test_utils::setup_test_keystore_from_fixtures;
use crate::test_utils::ALICE_MEMBER_HANDLE;
use secretenv_core::cli_api::test_support::storage::keystore::active::load_active_kid;
use secretenv_core::cli_api::test_support::storage::keystore::member::load_single_member_handle_from_keystore;
use secretenv_core::cli_api::test_support::storage::keystore::resolver::KeystoreResolver;
use secretenv_core::cli_api::test_support::storage::keystore::storage::load_public_key;
use secretenv_core::cli_api::test_support::storage::workspace::detection::resolve_workspace_creation_path;
use secretenv_core::cli_api::test_support::storage::workspace::setup::save_member_document;
use serial_test::serial;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// resolve_keystore_root tests
// ---------------------------------------------------------------------------

#[test]
fn test_resolve_keystore_root_with_home() {
    let tmp = TempDir::new().unwrap();
    let home = Some(tmp.path().to_path_buf());

    let root = KeystoreResolver::resolve(home.as_ref()).unwrap();

    assert_eq!(root, tmp.path().join("keys"));
}

#[test]
fn test_resolve_keystore_root_default() {
    // Without explicit home, resolve_keystore_root delegates to default config.
    // It should succeed and return a path ending with "keys".
    let root = KeystoreResolver::resolve(None).unwrap();

    assert!(
        root.ends_with("keys"),
        "Expected keystore root to end with 'keys', got: {}",
        root.display()
    );
}

// ---------------------------------------------------------------------------
// load_single_member_handle_from_keystore tests
// ---------------------------------------------------------------------------

#[test]
fn test_load_single_member_handle_from_keystore_one_member() {
    let tmp = TempDir::new().unwrap();
    let keystore_root = tmp.path().join("keys");
    std::fs::create_dir_all(keystore_root.join("alice@example.com")).unwrap();

    let result = load_single_member_handle_from_keystore(&keystore_root).unwrap();

    assert_eq!(result, Some("alice@example.com".to_string()));
}

#[test]
fn test_load_single_member_handle_from_keystore_multiple_members() {
    let tmp = TempDir::new().unwrap();
    let keystore_root = tmp.path().join("keys");
    std::fs::create_dir_all(keystore_root.join("alice@example.com")).unwrap();
    std::fs::create_dir_all(keystore_root.join("bob@example.com")).unwrap();

    let result = load_single_member_handle_from_keystore(&keystore_root).unwrap();

    assert_eq!(result, None);
}

#[test]
fn test_load_single_member_handle_from_keystore_no_members() {
    let tmp = TempDir::new().unwrap();
    let keystore_root = tmp.path().join("keys");
    std::fs::create_dir_all(&keystore_root).unwrap();

    let result = load_single_member_handle_from_keystore(&keystore_root).unwrap();

    assert_eq!(result, None);
}

#[test]
fn test_load_single_member_handle_from_keystore_nonexistent() {
    let tmp = TempDir::new().unwrap();
    let keystore_root = tmp.path().join("nonexistent_keys");

    let result = load_single_member_handle_from_keystore(&keystore_root).unwrap();

    assert_eq!(result, None);
}

// ---------------------------------------------------------------------------
// resolve_workspace_creation_path tests
// ---------------------------------------------------------------------------

#[test]
fn test_resolve_workspace_creation_path_explicit() {
    let tmp = TempDir::new().unwrap();
    let explicit_path = tmp.path().join("my_workspace");

    let result = resolve_workspace_creation_path(Some(explicit_path.clone())).unwrap();

    assert_eq!(result, explicit_path);
}

#[test]
#[serial]
fn test_resolve_workspace_creation_path_defaults_to_git_root_dot_secretenv() {
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
    let nested = tmp.path().join("nested").join("dir");
    std::fs::create_dir_all(&nested).unwrap();

    let original_dir = std::env::current_dir().unwrap();
    std::env::set_current_dir(&nested).unwrap();

    let result = resolve_workspace_creation_path(None).unwrap();

    std::env::set_current_dir(original_dir).unwrap();
    assert_eq!(
        result,
        tmp.path().canonicalize().unwrap().join(".secretenv")
    );
}

#[test]
#[serial]
fn test_resolve_workspace_creation_path_uses_current_dot_secretenv_without_git() {
    let tmp = TempDir::new().unwrap();
    let workspace_path = tmp.path().join(".secretenv");
    std::fs::create_dir_all(&workspace_path).unwrap();

    let original_dir = std::env::current_dir().unwrap();
    std::env::set_current_dir(tmp.path()).unwrap();

    let result = resolve_workspace_creation_path(None).unwrap();

    std::env::set_current_dir(original_dir).unwrap();
    assert_eq!(result, workspace_path.canonicalize().unwrap());
}

#[test]
#[serial]
fn test_resolve_workspace_creation_path_errors_without_git_or_current_dot_secretenv() {
    let tmp = TempDir::new().unwrap();

    let original_dir = std::env::current_dir().unwrap();
    std::env::set_current_dir(tmp.path()).unwrap();

    let result = resolve_workspace_creation_path(None);

    std::env::set_current_dir(original_dir).unwrap();
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// save_member_document tests
// ---------------------------------------------------------------------------

#[test]
fn test_save_member_document_creates_file() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    // Retrieve the active kid
    let kid = load_active_kid(ALICE_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .expect("Expected active kid to exist");

    // Prepare output directory and member file path
    let output_dir = temp_dir
        .path()
        .join("workspace")
        .join("members")
        .join("active");
    std::fs::create_dir_all(&output_dir).unwrap();
    let member_file = output_dir.join(format!("{}.json", ALICE_MEMBER_HANDLE));

    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &kid).unwrap();
    save_member_document(&member_file, &public_key).unwrap();

    assert!(member_file.exists(), "Member file should be created");

    // Verify the file contains valid JSON with expected fields
    let content = std::fs::read_to_string(&member_file).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert_eq!(
        json["protected"]["subject_handle"].as_str().unwrap(),
        ALICE_MEMBER_HANDLE
    );
    assert_eq!(json["protected"]["kid"].as_str().unwrap(), kid);
}
