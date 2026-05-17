// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for workspace members

use crate::test_utils::{
    keygen_test, setup_test_workspace, ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE,
};
use secretenv_core::cli_api::test_support::storage::workspace::members::{
    list_active_member_handles, load_active_member_files, load_member_file,
    load_verified_member_file_from_path,
};
use std::fs;
use tempfile::TempDir;

#[test]
fn test_list_member_handles() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_root = temp_dir.path();
    std::fs::create_dir_all(workspace_root.join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_root.join("members/incoming")).unwrap();
    let active_dir = workspace_root.join("members/active");

    // Create member files
    std::fs::write(active_dir.join("alice@example.com.json"), "{}").unwrap();
    std::fs::write(active_dir.join("bob@example.com.json"), "{}").unwrap();
    std::fs::write(active_dir.join("charlie@example.com.json"), "{}").unwrap();

    let result = list_active_member_handles(workspace_root).unwrap();
    assert_eq!(
        result,
        vec![
            "alice@example.com".to_string(),
            "bob@example.com".to_string(),
            "charlie@example.com".to_string()
        ]
    );
}

#[test]
fn test_list_member_handles_empty() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_root = temp_dir.path();
    std::fs::create_dir_all(workspace_root.join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_root.join("members/incoming")).unwrap();

    let result = list_active_member_handles(workspace_root);
    assert!(result.is_err());
}

#[test]
fn test_load_verified_member_file_accepts_matching_stem() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);
    let path = workspace_dir
        .join("members/active")
        .join(format!("{}.json", ALICE_MEMBER_HANDLE));

    let public_key = load_verified_member_file_from_path(&path).unwrap();
    assert_eq!(public_key.protected.subject_handle, ALICE_MEMBER_HANDLE);
    drop(temp_dir);
}

#[test]
fn test_load_verified_member_file_rejects_mismatched_stem() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);
    let members_dir = workspace_dir.join("members/active");

    let ssh_pub_content = fs::read_to_string(temp_dir.path().join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let ssh_priv = temp_dir.path().join(".ssh/test_ed25519");
    let (_bob_private, bob_public) =
        keygen_test(BOB_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();

    // File stem says alice but the document carries bob's member_handle.
    let tampered = members_dir.join(format!("{}.json", ALICE_MEMBER_HANDLE));
    fs::write(
        &tampered,
        serde_json::to_string_pretty(&bob_public).unwrap(),
    )
    .unwrap();

    let err = load_verified_member_file_from_path(&tampered).unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("Member handle mismatch"),
        "unexpected error: {message}"
    );
}

#[test]
fn test_load_active_member_files_rejects_mismatched_stem_in_bulk() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);
    let members_dir = workspace_dir.join("members/active");

    let ssh_pub_content = fs::read_to_string(temp_dir.path().join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let ssh_priv = temp_dir.path().join(".ssh/test_ed25519");
    let (_bob_private, bob_public) =
        keygen_test(BOB_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();

    // Overwrite alice's file with bob's document.
    let tampered = members_dir.join(format!("{}.json", ALICE_MEMBER_HANDLE));
    fs::write(
        &tampered,
        serde_json::to_string_pretty(&bob_public).unwrap(),
    )
    .unwrap();

    let err = load_active_member_files(&workspace_dir).unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("Member handle mismatch"),
        "unexpected error: {message}"
    );
}

#[test]
fn test_load_member_file_rejects_mismatched_stem() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);
    let members_dir = workspace_dir.join("members/active");

    let ssh_pub_content = fs::read_to_string(temp_dir.path().join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let ssh_priv = temp_dir.path().join(".ssh/test_ed25519");
    let (_bob_private, bob_public) =
        keygen_test(BOB_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();

    let tampered = members_dir.join(format!("{}.json", ALICE_MEMBER_HANDLE));
    fs::write(
        &tampered,
        serde_json::to_string_pretty(&bob_public).unwrap(),
    )
    .unwrap();

    let err = load_member_file(&workspace_dir, ALICE_MEMBER_HANDLE).unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("Member handle mismatch"),
        "unexpected error: {message}"
    );
}
