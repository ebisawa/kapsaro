// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::test_utils::setup_test_keystore_from_fixtures;
use crate::test_utils::ALICE_MEMBER_HANDLE;
use kapsaro_core::cli_api::test_support::storage::keystore::member::{
    find_active_key_document, load_public_keys_for_member, load_single_member_handle_from_keystore,
};
use tempfile::TempDir;

#[test]
fn test_load_single_member_handle_from_keystore_returns_single_member() {
    let temp_dir = TempDir::new().unwrap();
    let keystore_root = temp_dir.path().join("keys");
    std::fs::create_dir_all(keystore_root.join(ALICE_MEMBER_HANDLE)).unwrap();

    let member_handle = load_single_member_handle_from_keystore(&keystore_root).unwrap();

    assert_eq!(member_handle, Some(ALICE_MEMBER_HANDLE.to_string()));
}

#[test]
fn test_find_active_key_document_returns_active_key() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let active = find_active_key_document(ALICE_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .expect("expected active key");

    assert_eq!(
        active.public_key.protected.subject_handle,
        ALICE_MEMBER_HANDLE
    );
    assert_eq!(active.kid, active.public_key.protected.kid);
}

#[test]
fn test_load_public_keys_for_member_returns_all_local_keys() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let public_keys = load_public_keys_for_member(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();

    assert_eq!(public_keys.len(), 1);
    assert_eq!(public_keys[0].protected.subject_handle, ALICE_MEMBER_HANDLE);
}
