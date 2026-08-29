// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for workspace members

use crate::io::workspace::members::{
    list_active_member_paths, load_active_member_files, load_member_file,
    load_verified_member_file_from_path, open_member_documents_at, MemberStatus,
};
use crate::support::fs::relative::{open_dir_nofollow, DirectoryScope};
use crate::test_utils::{
    keygen_test, setup_test_workspace, ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE,
};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[test]
fn test_load_active_member_files_returns_documents_sorted_by_subject_handle() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[BOB_MEMBER_HANDLE, ALICE_MEMBER_HANDLE]);

    let members = load_active_member_files(&workspace_dir).unwrap();

    let handles: Vec<&str> = members
        .iter()
        .map(|member| member.protected.subject_handle.as_str())
        .collect();
    assert_eq!(handles, vec![ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    drop(temp_dir);
}

#[test]
fn test_load_active_member_files_reports_an_empty_set_for_a_workspace_without_members() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_root = temp_dir.path();
    fs::create_dir_all(workspace_root.join("members/active")).unwrap();
    fs::create_dir_all(workspace_root.join("members/incoming")).unwrap();

    let members = load_active_member_files(workspace_root).unwrap();

    assert!(members.is_empty());
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

fn active_member_document_path(workspace_dir: &Path, member_handle: &str) -> PathBuf {
    workspace_dir
        .join("members/active")
        .join(format!("{}.json", member_handle))
}

fn assert_refuses_non_regular_entry(message: &str, member_handle: &str) {
    assert!(
        message.contains("refusing to use non-regular file"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains(&format!("{}.json", member_handle)),
        "error does not name the entry: {message}"
    );
}

#[test]
fn test_load_active_member_files_rejects_a_directory_named_like_a_member_document() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);
    fs::create_dir(active_member_document_path(
        &workspace_dir,
        BOB_MEMBER_HANDLE,
    ))
    .unwrap();

    let err = load_active_member_files(&workspace_dir).unwrap_err();

    assert_refuses_non_regular_entry(&err.to_string(), BOB_MEMBER_HANDLE);
}

#[test]
fn test_load_active_member_files_rejects_a_symlink_named_like_a_member_document() {
    use std::os::unix::fs::symlink;

    let (_temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);
    symlink(
        active_member_document_path(&workspace_dir, ALICE_MEMBER_HANDLE),
        active_member_document_path(&workspace_dir, BOB_MEMBER_HANDLE),
    )
    .unwrap();

    let err = load_active_member_files(&workspace_dir).unwrap_err();

    assert_refuses_non_regular_entry(&err.to_string(), BOB_MEMBER_HANDLE);
}

#[test]
fn test_list_active_member_paths_rejects_a_directory_named_like_a_member_document() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);
    fs::create_dir(active_member_document_path(
        &workspace_dir,
        BOB_MEMBER_HANDLE,
    ))
    .unwrap();

    let err = list_active_member_paths(&workspace_dir).unwrap_err();

    assert_refuses_non_regular_entry(&err.to_string(), BOB_MEMBER_HANDLE);
}

/// A diagnosis judges every name on its own, so an entry that is not a regular
/// file stays in the listing and fails when it is read.
#[test]
fn test_open_member_documents_reports_a_directory_named_like_a_member_document_on_read() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_root = temp_dir.path();
    fs::create_dir_all(workspace_root.join("members/active")).unwrap();
    fs::create_dir(active_member_document_path(
        workspace_root,
        BOB_MEMBER_HANDLE,
    ))
    .unwrap();
    let workspace = open_dir_nofollow(workspace_root, DirectoryScope::Generic).unwrap();

    let documents = open_member_documents_at(&workspace, MemberStatus::Active).unwrap();

    let name = format!("{}.json", BOB_MEMBER_HANDLE);
    assert_eq!(documents.names(), std::slice::from_ref(&name));
    assert!(documents.load(&name).is_err());
}
