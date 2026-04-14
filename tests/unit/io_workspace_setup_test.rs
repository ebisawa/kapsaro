// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::test_utils::setup_test_keystore_from_fixtures;
use crate::test_utils::ALICE_MEMBER_ID;
use secretenv::io::keystore::active::load_active_kid;
use secretenv::io::keystore::storage::load_public_key;
use secretenv::io::workspace::setup::{
    ensure_workspace_structure, save_member_document, validate_workspace_exists,
    workspace_has_active_members,
};
use tempfile::TempDir;

#[test]
fn test_ensure_workspace_structure_creates_required_directories() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_path = temp_dir.path().join(".secretenv");

    let created = ensure_workspace_structure(&workspace_path).unwrap();

    assert!(created);
    assert!(workspace_path.join("members/active/.gitkeep").exists());
    assert!(workspace_path.join("members/incoming/.gitkeep").exists());
    assert!(workspace_path.join("secrets/.gitkeep").exists());
}

#[test]
fn test_validate_workspace_exists_accepts_complete_workspace() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_path = temp_dir.path().join(".secretenv");
    ensure_workspace_structure(&workspace_path).unwrap();

    validate_workspace_exists(&workspace_path).unwrap();
}

#[test]
fn test_ensure_workspace_structure_completes_missing_incoming_directory() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_path = temp_dir.path().join(".secretenv");
    std::fs::create_dir_all(workspace_path.join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_path.join("secrets")).unwrap();

    let created = ensure_workspace_structure(&workspace_path).unwrap();

    assert!(created);
    assert!(workspace_path.join("members/incoming/.gitkeep").exists());
}

#[test]
fn test_workspace_has_active_members_ignores_gitkeep_only_directory() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_path = temp_dir.path().join(".secretenv");
    ensure_workspace_structure(&workspace_path).unwrap();

    let has_active_members = workspace_has_active_members(&workspace_path).unwrap();

    assert!(!has_active_members);
}

#[test]
fn test_workspace_has_active_members_detects_json_member_file() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_path = temp_dir.path().join(".secretenv");
    ensure_workspace_structure(&workspace_path).unwrap();
    std::fs::write(
        workspace_path.join("members/active/alice@example.com.json"),
        "{}",
    )
    .unwrap();

    let has_active_members = workspace_has_active_members(&workspace_path).unwrap();

    assert!(has_active_members);
}

#[test]
fn test_save_member_document_writes_public_key_json() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");
    let kid = load_active_kid(ALICE_MEMBER_ID, &keystore_root)
        .unwrap()
        .expect("Expected active kid");
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, &kid).unwrap();
    let member_file = temp_dir
        .path()
        .join("workspace")
        .join("members")
        .join("active")
        .join(format!("{ALICE_MEMBER_ID}.json"));
    std::fs::create_dir_all(member_file.parent().unwrap()).unwrap();

    save_member_document(&member_file, &public_key).unwrap();

    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&member_file).unwrap()).unwrap();
    assert_eq!(
        saved["protected"]["member_id"].as_str().unwrap(),
        ALICE_MEMBER_ID
    );
    assert_eq!(saved["protected"]["kid"].as_str().unwrap(), kid);
}
