// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::select_verification_member_files;
use crate::test_utils::{
    setup_test_workspace_from_fixtures, ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE,
};

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

fn path_has_member_filename(path: &std::path::Path, member_handle: &str) -> bool {
    let expected_file_name = format!("{}.json", member_handle);
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == expected_file_name)
}
