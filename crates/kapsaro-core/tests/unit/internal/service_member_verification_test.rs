// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::select_verification_member_names;
use crate::io::workspace::members::{open_member_documents_at, MemberStatus};
use crate::service::member::query::{list_members, load_member_show_result};
use crate::service::workspace::{WorkspaceAccess, WorkspaceKind};
use crate::test_utils::{
    setup_test_workspace_from_fixtures, ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE,
};
use serde_json::Value;
use std::fs;

fn active_names(workspace: &std::path::Path) -> Vec<String> {
    let access = WorkspaceAccess::open(workspace, WorkspaceKind::Regular).unwrap();
    open_member_documents_at(access.directory(), MemberStatus::Active)
        .unwrap()
        .names()
        .to_vec()
}

fn save_tampered_incoming_member(workspace_dir: &std::path::Path, member_handle: &str) {
    let incoming_dir = workspace_dir.join("members").join("incoming");
    fs::create_dir_all(&incoming_dir).unwrap();
    let source_file = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", ALICE_MEMBER_HANDLE));
    let incoming_file = incoming_dir.join(format!("{member_handle}.json"));
    fs::copy(source_file, &incoming_file).unwrap();

    let mut value: Value =
        serde_json::from_str(&fs::read_to_string(&incoming_file).unwrap()).unwrap();
    value["protected"]["attestation"]["sig"] = Value::String("broken".to_string());
    fs::write(incoming_file, serde_json::to_string_pretty(&value).unwrap()).unwrap();
}

#[test]
fn test_select_verification_member_names_returns_all_active_members() {
    let (_temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);

    let files = select_verification_member_names(&active_names(&workspace_dir), &[]).unwrap();

    assert_eq!(files.len(), 2);
    assert!(files
        .iter()
        .any(|name| name == &format!("{ALICE_MEMBER_HANDLE}.json")));
    assert!(files
        .iter()
        .any(|name| name == &format!("{BOB_MEMBER_HANDLE}.json")));
}

#[test]
fn test_select_verification_member_names_returns_requested_active_member() {
    let (_temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);

    let files = select_verification_member_names(
        &active_names(&workspace_dir),
        &[BOB_MEMBER_HANDLE.to_string()],
    )
    .unwrap();

    assert_eq!(files.len(), 1);
    let expected_file_name = format!("{}.json", BOB_MEMBER_HANDLE);
    assert_eq!(files[0], expected_file_name);
}

#[test]
fn test_select_verification_member_names_rejects_missing_active_member() {
    let (_temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);

    let error = select_verification_member_names(
        &active_names(&workspace_dir),
        &[BOB_MEMBER_HANDLE.to_string()],
    )
    .unwrap_err();

    assert!(error
        .to_string()
        .contains("Member 'bob@example.com' not found in active/"));
}

#[test]
fn test_list_members_skips_invalid_incoming_member_file() {
    let (_temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    save_tampered_incoming_member(&workspace_dir, BOB_MEMBER_HANDLE);

    let result =
        list_members(&WorkspaceAccess::open(&workspace_dir, WorkspaceKind::Regular).unwrap())
            .unwrap();

    assert_eq!(result.active.len(), 1);
    assert_eq!(result.active[0].member_handle, ALICE_MEMBER_HANDLE);
    assert!(result.incoming.is_empty());
    assert_eq!(result.warnings.len(), 1);
    assert!(result.warnings[0].contains("Skipping invalid member file"));
    assert!(result.warnings[0].contains(BOB_MEMBER_HANDLE));
}

#[test]
fn test_select_verification_member_names_selects_active_scope_with_invalid_incoming() {
    let (_temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    save_tampered_incoming_member(&workspace_dir, BOB_MEMBER_HANDLE);

    let files = select_verification_member_names(&active_names(&workspace_dir), &[]).unwrap();

    assert_eq!(files.len(), 1);
    assert_eq!(files[0], format!("{ALICE_MEMBER_HANDLE}.json"));
}

/// A handle names one entry of `members/active`, so one carrying path
/// components is refused as a handle rather than joined onto the directory and
/// read from wherever it lands.
#[test]
fn test_select_verification_member_names_rejects_a_traversing_member_handle() {
    let (_temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);

    let error = select_verification_member_names(
        &active_names(&workspace_dir),
        &["../../etc/hosts".to_string()],
    )
    .unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidArgument);
    assert!(
        error.format_user_message().contains("member_handle"),
        "{}",
        error.format_user_message()
    );
}

/// The same handle reaches the show query, which looks the name up in both the
/// active and the incoming directory.
#[test]
fn test_load_member_show_result_rejects_a_traversing_member_handle() {
    let (_temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);

    let error = load_member_show_result(
        &WorkspaceAccess::open(&workspace_dir, WorkspaceKind::Regular).unwrap(),
        "../../etc/hosts",
    )
    .unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidArgument);
    assert!(
        error.format_user_message().contains("member_handle"),
        "{}",
        error.format_user_message()
    );
}
