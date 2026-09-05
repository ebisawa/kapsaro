// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::io::keystore::access::KeystoreAccess;
use crate::io::keystore::access::PublicKeySnapshotEntry;
use crate::io::keystore::member::{
    find_active_key_document, load_single_member_handle_from_keystore,
};
use crate::model::identity::MemberHandle;
use crate::test_utils::setup_test_keystore_from_fixtures;
use crate::test_utils::ALICE_MEMBER_HANDLE;
use crate::test_utils::{ensure_local_state_dir, local_state_temp_dir};

#[test]
fn test_load_single_member_handle_from_keystore_returns_single_member() {
    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path().join("keys");
    ensure_local_state_dir(&keystore_root.join(ALICE_MEMBER_HANDLE));

    let access = KeystoreAccess::open(&keystore_root).unwrap();
    let member_handle = load_single_member_handle_from_keystore(&access).unwrap();

    assert_eq!(
        member_handle.as_ref().map(MemberHandle::as_str),
        Some(ALICE_MEMBER_HANDLE)
    );
}

#[test]
fn test_find_active_key_document_returns_active_key() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let access = KeystoreAccess::open(&keystore_root).unwrap();
    let member_handle = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let active = find_active_key_document(&access, &member_handle)
        .unwrap()
        .expect("expected active key");

    assert_eq!(
        active.public_key.protected.subject_handle,
        ALICE_MEMBER_HANDLE
    );
    assert_eq!(active.kid, active.public_key.protected.kid);
}

#[test]
fn test_keystore_access_load_public_key_entries_returns_all_local_keys() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let access = KeystoreAccess::open(&keystore_root).unwrap();
    let member_handle = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let (_, entries) = access
        .load_public_key_entries_with_active(&member_handle)
        .unwrap();
    let public_keys: Vec<_> = entries
        .into_iter()
        .filter_map(|entry| match entry {
            PublicKeySnapshotEntry::Complete { public_key, .. } => Some(public_key),
            PublicKeySnapshotEntry::MissingPublicDocument { .. } => None,
        })
        .collect();

    assert_eq!(public_keys.len(), 1);
    assert_eq!(public_keys[0].protected.subject_handle, ALICE_MEMBER_HANDLE);
}
