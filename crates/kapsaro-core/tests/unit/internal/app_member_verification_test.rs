// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::select_verification_member_files;
use crate::app::member::query::list_members;
use crate::app_test_utils::build_test_signing_command_options;
use crate::test_utils::{
    setup_test_workspace_from_fixtures, ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE,
};
use serde_json::Value;
use std::fs;

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
fn test_select_verification_member_files_returns_all_active_members() {
    let (_temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);

    let files = select_verification_member_files(&workspace_dir, &[]).unwrap();

    assert_eq!(files.len(), 2);
    assert!(files
        .iter()
        .any(|path| path_has_member_filename(path, ALICE_MEMBER_HANDLE)));
    assert!(files
        .iter()
        .any(|path| path_has_member_filename(path, BOB_MEMBER_HANDLE)));
}

#[test]
fn test_select_verification_member_files_returns_requested_active_member() {
    let (_temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);

    let files =
        select_verification_member_files(&workspace_dir, &[BOB_MEMBER_HANDLE.to_string()]).unwrap();

    assert_eq!(files.len(), 1);
    let expected_file_name = format!("{}.json", BOB_MEMBER_HANDLE);
    assert_eq!(
        files[0].file_name().and_then(|name| name.to_str()),
        Some(expected_file_name.as_str())
    );
}

#[test]
fn test_select_verification_member_files_rejects_missing_active_member() {
    let (_temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);

    let error = select_verification_member_files(&workspace_dir, &[BOB_MEMBER_HANDLE.to_string()])
        .unwrap_err();

    assert!(error
        .to_string()
        .contains("Member 'bob@example.com' not found in active/"));
}

#[test]
fn test_list_members_skips_invalid_incoming_member_file() {
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    save_tampered_incoming_member(&workspace_dir, BOB_MEMBER_HANDLE);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);

    let result = list_members(&options).unwrap();

    assert_eq!(result.active.len(), 1);
    assert_eq!(result.active[0].member_handle, ALICE_MEMBER_HANDLE);
    assert!(result.incoming.is_empty());
    assert_eq!(result.warnings.len(), 1);
    assert!(result.warnings[0].contains("Skipping invalid member file"));
    assert!(result.warnings[0].contains(BOB_MEMBER_HANDLE));
}

#[test]
fn test_select_verification_member_files_ignores_invalid_incoming_member() {
    let (_temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    save_tampered_incoming_member(&workspace_dir, BOB_MEMBER_HANDLE);

    let files = select_verification_member_files(&workspace_dir, &[]).unwrap();

    assert_eq!(files.len(), 1);
    assert!(path_has_member_filename(&files[0], ALICE_MEMBER_HANDLE));
}

fn path_has_member_filename(path: &std::path::Path, member_handle: &str) -> bool {
    let expected_file_name = format!("{}.json", member_handle);
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == expected_file_name)
}
