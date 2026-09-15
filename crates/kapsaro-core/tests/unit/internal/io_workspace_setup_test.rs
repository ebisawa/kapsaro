// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::io::workspace::members::{save_member_content, MemberStatus};
use crate::io::workspace::setup::{ensure_workspace_structure_at, inspect_workspace_structure_at};
use crate::service::workspace::{WorkspaceAccess, WorkspaceCreationTarget, WorkspaceKind};
use crate::test_support::storage::keystore::active::load_active_kid;
use crate::test_support::storage::keystore::storage::load_public_key;
use crate::test_utils::setup_test_keystore_from_fixtures;
use crate::test_utils::ALICE_MEMBER_HANDLE;
use std::fs;
use tempfile::TempDir;

fn select_creation_target(path: &std::path::Path) -> WorkspaceCreationTarget {
    WorkspaceCreationTarget::open(path, WorkspaceKind::Regular).unwrap()
}

#[test]
fn test_ensure_workspace_structure_creates_required_directories() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_path = temp_dir.path().join(".kapsaro");

    let workspace = select_creation_target(&workspace_path).ensure().unwrap();
    let created = ensure_workspace_structure_at(workspace.directory()).unwrap();

    assert!(created);
    assert!(workspace_path.join("members/active/.gitkeep").exists());
    assert!(workspace_path.join("members/incoming/.gitkeep").exists());
    assert!(workspace_path.join("secrets/.gitkeep").exists());
}

#[test]
fn test_validate_workspace_exists_accepts_complete_workspace() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_path = temp_dir.path().join(".kapsaro");
    let workspace = select_creation_target(&workspace_path).ensure().unwrap();
    ensure_workspace_structure_at(workspace.directory()).unwrap();

    workspace.validate().unwrap();
    assert!(inspect_workspace_structure_at(workspace.directory()).unwrap());
}

#[test]
fn test_ensure_workspace_structure_completes_missing_incoming_directory() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_path = temp_dir.path().join(".kapsaro");
    std::fs::create_dir_all(workspace_path.join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_path.join("secrets")).unwrap();

    let workspace = select_creation_target(&workspace_path).ensure().unwrap();
    let created = ensure_workspace_structure_at(workspace.directory()).unwrap();

    assert!(created);
    assert!(workspace_path.join("members/incoming/.gitkeep").exists());
}

/// The member store writes into the very tree this setup builds, so a document
/// saved right after it lands in the active directory the structure created.
#[test]
fn test_member_document_lands_in_the_structure_setup_created() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");
    let kid = load_active_kid(ALICE_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .expect("Expected active kid");
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &kid).unwrap();
    // A workspace of this test's own: the keystore fixture builds one beside the
    // keys and installs the member into it, which would make this a replacement
    // rather than the first write into a structure setup just created.
    let workspace_path = temp_dir.path().join("workspace-under-test");
    let workspace = select_creation_target(&workspace_path).ensure().unwrap();
    ensure_workspace_structure_at(workspace.directory()).unwrap();

    save_member_content(
        workspace.directory(),
        MemberStatus::Active,
        ALICE_MEMBER_HANDLE,
        &serde_json::to_string_pretty(&public_key).unwrap(),
        false,
    )
    .unwrap();

    let member_file = workspace_path
        .join("members")
        .join("active")
        .join(format!("{ALICE_MEMBER_HANDLE}.json"));
    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&member_file).unwrap()).unwrap();
    assert_eq!(
        saved["protected"]["subject_handle"].as_str().unwrap(),
        ALICE_MEMBER_HANDLE
    );
    assert_eq!(saved["protected"]["kid"].as_str().unwrap(), kid);
}

#[cfg(unix)]
#[test]
fn test_ensure_workspace_structure_rejects_symlinked_members_directory() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let workspace_path = temp_dir.path().join(".kapsaro");
    let outside_dir = temp_dir.path().join("outside");
    fs::create_dir(&workspace_path).unwrap();
    fs::create_dir(&outside_dir).unwrap();
    symlink(&outside_dir, workspace_path.join("members")).unwrap();

    let workspace = select_creation_target(&workspace_path).ensure().unwrap();
    let error = ensure_workspace_structure_at(workspace.directory()).unwrap_err();

    assert!(error.to_string().contains("symlink"));
    assert!(
        !outside_dir.join("active/.gitkeep").exists(),
        "workspace setup must not create directories through a symlinked ancestor"
    );
}

#[cfg(unix)]
#[test]
fn test_validate_workspace_exists_rejects_symlinked_secrets_directory() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let workspace_path = temp_dir.path().join(".kapsaro");
    let outside_dir = temp_dir.path().join("outside");
    fs::create_dir_all(workspace_path.join("members/active")).unwrap();
    fs::create_dir_all(workspace_path.join("members/incoming")).unwrap();
    fs::create_dir(&outside_dir).unwrap();
    symlink(&outside_dir, workspace_path.join("secrets")).unwrap();

    let workspace = WorkspaceAccess::open(&workspace_path, WorkspaceKind::Regular).unwrap();
    let error = workspace.validate().unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert!(error.to_string().contains("symlink"));
}
