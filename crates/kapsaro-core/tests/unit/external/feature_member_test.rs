// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for core/usecase/member module
//!
//! Tests for member management use cases.

use crate::test_utils::setup_test_workspace;
use crate::test_utils::ALICE_MEMBER_HANDLE;
use kapsaro_core::cli_api::test_support::operations::member::verification::verify_member_files;
use kapsaro_core::cli_api::test_support::storage::workspace::members::{
    load_active_member_files, load_member_file, remove_member,
};
use tempfile::TempDir;

#[test]
fn test_member_list() {
    let (_temp_dir, workspace_dir) =
        setup_test_workspace(&[ALICE_MEMBER_HANDLE, "bob@example.com"]);

    let members = load_active_member_files(&workspace_dir).unwrap();

    assert_eq!(members.len(), 2);
    let member_handles: Vec<String> = members
        .iter()
        .map(|m| m.protected.subject_handle.clone())
        .collect();
    assert!(member_handles.contains(&ALICE_MEMBER_HANDLE.to_string()));
    assert!(member_handles.contains(&"bob@example.com".to_string()));
}

#[test]
fn test_member_list_empty() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_dir = temp_dir.path().join("workspace");
    std::fs::create_dir_all(workspace_dir.join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_dir.join("members/incoming")).unwrap();

    let members = load_active_member_files(&workspace_dir).unwrap();

    assert_eq!(members.len(), 0);
}

#[test]
fn test_member_show() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);

    let (member, _status) = load_member_file(&workspace_dir, ALICE_MEMBER_HANDLE).unwrap();

    assert_eq!(member.protected.subject_handle, ALICE_MEMBER_HANDLE);
}

#[test]
fn test_member_show_not_found() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);

    let result = load_member_file(&workspace_dir, "nonexistent@example.com");

    assert!(result.is_err());
}

#[test]
fn test_member_remove() {
    let (_temp_dir, workspace_dir) =
        setup_test_workspace(&[ALICE_MEMBER_HANDLE, "bob@example.com"]);

    remove_member(&workspace_dir, ALICE_MEMBER_HANDLE).unwrap();

    // alice should no longer be in active/
    let members = load_active_member_files(&workspace_dir).unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].protected.subject_handle, "bob@example.com");
}

#[tokio::test]
async fn test_verify_member_all() {
    let (_temp_dir, workspace_dir) =
        setup_test_workspace(&[ALICE_MEMBER_HANDLE, "bob@example.com"]);
    let member_files = vec![
        active_member_path(&workspace_dir, ALICE_MEMBER_HANDLE),
        active_member_path(&workspace_dir, "bob@example.com"),
    ];

    let result = verify_member_files(&member_files, false).await;

    assert_eq!(result.len(), 2);
}

#[tokio::test]
async fn test_verify_member_files_accepts_selected_member_file() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);
    let member_files = vec![active_member_path(&workspace_dir, ALICE_MEMBER_HANDLE)];

    let result = verify_member_files(&member_files, false).await;

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].member_handle, ALICE_MEMBER_HANDLE);
}

#[tokio::test]
async fn test_verify_member_files_reports_offline_verification_failure() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);
    let alice_active = active_member_path(&workspace_dir, ALICE_MEMBER_HANDLE);
    std::fs::write(&alice_active, b"{").unwrap();

    let result = verify_member_files(&[alice_active], false).await;

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].member_handle, ALICE_MEMBER_HANDLE);
    assert!(result[0].message.contains("Offline verification failed:"));
}

fn active_member_path(workspace_dir: &std::path::Path, member_handle: &str) -> std::path::PathBuf {
    workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", member_handle))
}
