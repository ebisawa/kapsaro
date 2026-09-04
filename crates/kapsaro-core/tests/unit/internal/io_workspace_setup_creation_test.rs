// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for workspace directory creation in the io/workspace/setup module.

use crate::io::workspace::detection::resolve_workspace_creation_path_from;
use crate::test_support::storage::keystore::member::load_single_member_handle_from_keystore;
use crate::test_utils::{ensure_local_state_dir, local_state_temp_dir};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// load_single_member_handle_from_keystore tests
// ---------------------------------------------------------------------------

#[test]
fn test_load_single_member_handle_from_keystore_one_member() {
    let tmp = local_state_temp_dir();
    let keystore_root = tmp.path().join("keys");
    ensure_local_state_dir(&keystore_root.join("alice@example.com"));

    let result = load_single_member_handle_from_keystore(&keystore_root).unwrap();

    assert_eq!(result, Some("alice@example.com".to_string()));
}

#[test]
fn test_load_single_member_handle_from_keystore_multiple_members() {
    let tmp = local_state_temp_dir();
    let keystore_root = tmp.path().join("keys");
    ensure_local_state_dir(&keystore_root.join("alice@example.com"));
    ensure_local_state_dir(&keystore_root.join("bob@example.com"));

    let result = load_single_member_handle_from_keystore(&keystore_root).unwrap();

    assert_eq!(result, None);
}

#[test]
fn test_load_single_member_handle_from_keystore_no_members() {
    let tmp = local_state_temp_dir();
    let keystore_root = tmp.path().join("keys");
    ensure_local_state_dir(&keystore_root);

    let result = load_single_member_handle_from_keystore(&keystore_root).unwrap();

    assert_eq!(result, None);
}

#[test]
fn test_load_single_member_handle_from_keystore_nonexistent() {
    let tmp = local_state_temp_dir();
    let keystore_root = tmp.path().join("nonexistent_keys");

    let result = load_single_member_handle_from_keystore(&keystore_root).unwrap();

    assert_eq!(result, None);
}

// ---------------------------------------------------------------------------
// resolve_workspace_creation_path tests
// ---------------------------------------------------------------------------

#[test]
fn test_resolve_workspace_creation_path_defaults_to_git_root_dot_kapsaro() {
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
    let nested = tmp.path().join("nested").join("dir");
    std::fs::create_dir_all(&nested).unwrap();

    let result = resolve_workspace_creation_path_from(&nested).unwrap();

    assert_eq!(result, tmp.path().canonicalize().unwrap().join(".kapsaro"));
}

#[test]
fn test_resolve_workspace_creation_path_uses_current_dot_kapsaro_without_git() {
    let tmp = TempDir::new().unwrap();
    let workspace_path = tmp.path().join(".kapsaro");
    std::fs::create_dir_all(&workspace_path).unwrap();

    let result = resolve_workspace_creation_path_from(tmp.path()).unwrap();

    assert_eq!(result, workspace_path.canonicalize().unwrap());
}

#[test]
fn test_resolve_workspace_creation_path_errors_without_git_or_current_dot_kapsaro() {
    let tmp = TempDir::new().unwrap();

    let result = resolve_workspace_creation_path_from(tmp.path());

    assert!(result.is_err());
}
