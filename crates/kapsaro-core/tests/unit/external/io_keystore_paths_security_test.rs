// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public keystore filesystem-security regression tests.
//! Verifies that typed handles and pinned directory descriptors prevent redirection.

use crate::test_utils::local_state_temp_dir;
use kapsaro_core::api::key::{Kid, LocalKeyStore, MemberHandle};
use kapsaro_core::{Error, ErrorKind};
use std::fs;

const TEST_KID: &str = "00000000000000000000000000000000";

fn test_kid() -> Kid {
    Kid::try_from(TEST_KID).expect("valid test kid")
}

fn assert_local_state_path_unsafe(error: &Error) {
    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
}

#[cfg(unix)]
use std::os::unix::fs::symlink;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// A keystore root placed behind a symlink is a deliberate setup, so the store
/// opens through the link and works on the directory it resolved to.
#[cfg(unix)]
#[test]
fn test_local_key_store_open_opens_through_a_root_symlink() {
    let temp = local_state_temp_dir();
    let outside = temp.path().join("outside");
    let root = temp.path().join("keys");
    fs::create_dir(&outside).unwrap();
    fs::create_dir(outside.join("alice@example.com")).unwrap();
    symlink(&outside, &root).unwrap();

    let store = LocalKeyStore::open(&root).unwrap();

    assert_eq!(
        store.list_members().unwrap(),
        vec![MemberHandle::try_from("alice@example.com").unwrap()]
    );
}

#[cfg(unix)]
#[test]
fn test_local_key_store_create_opens_through_a_root_symlink() {
    let temp = local_state_temp_dir();
    let outside = temp.path().join("outside");
    let root = temp.path().join("keys");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, &root).unwrap();

    let store = LocalKeyStore::ensure(&root).unwrap();
    fs::create_dir(outside.join("alice@example.com")).unwrap();

    assert_eq!(
        store.list_members().unwrap(),
        vec![MemberHandle::try_from("alice@example.com").unwrap()]
    );
}

#[cfg(unix)]
#[test]
fn test_local_key_store_create_preserves_existing_ancestor_mode() {
    let temp = local_state_temp_dir();
    let ancestor = temp.path().join("shared");
    fs::create_dir(&ancestor).unwrap();
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o755)).unwrap();
    let home = ancestor.join("home");
    let root = home.join("keys");

    LocalKeyStore::ensure(&root).unwrap();

    assert_eq!(
        fs::metadata(&ancestor).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(
        fs::metadata(&home).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[cfg(unix)]
#[test]
fn test_local_key_store_create_follows_existing_ancestor_symlink() {
    let temp = local_state_temp_dir();
    let outside = temp.path().join("outside");
    let alias = temp.path().join("alias");
    fs::create_dir(&outside).unwrap();
    // The link target becomes an ancestor of the keystore, so it has to be
    // owner-only for the subject of this test to be the symlink alone.
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&outside, &alias).unwrap();
    let root = alias.join("home/keys");

    LocalKeyStore::ensure(&root).unwrap();

    assert!(outside.join("home/keys").is_dir());
}

#[cfg(unix)]
#[test]
fn test_local_key_store_rejects_member_symlink_for_read_and_write() {
    let temp = local_state_temp_dir();
    let outside = temp.path().join("outside");
    let root = temp.path().join("keys");
    fs::create_dir(&outside).unwrap();
    let store = LocalKeyStore::ensure(&root).unwrap();
    symlink(&outside, root.join("alice@example.com")).unwrap();
    let member = MemberHandle::try_from("alice@example.com").unwrap();

    let list_error = store.list_kids(&member).unwrap_err();
    let write_error = store.set_active_kid(&member, &test_kid()).unwrap_err();

    assert_local_state_path_unsafe(&list_error);
    assert_local_state_path_unsafe(&write_error);
    assert!(!outside.join("active").exists());
}

/// The store keeps reading the directory it opened, so replacing the path it
/// was given afterwards cannot feed it another tree.
#[cfg(unix)]
#[test]
fn test_local_key_store_stays_bound_to_opened_root_after_path_swap() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let original = temp.path().join("keys.original");
    let outside = temp.path().join("outside");
    let store = LocalKeyStore::ensure(&root).unwrap();
    fs::create_dir(root.join("alice@example.com")).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::create_dir(outside.join("mallory@example.com")).unwrap();
    fs::rename(&root, &original).unwrap();
    symlink(&outside, &root).unwrap();

    let members = store.list_members().unwrap();

    assert_eq!(
        members,
        vec![MemberHandle::try_from("alice@example.com").unwrap()]
    );
}

#[test]
fn test_local_key_store_missing_member_has_no_keys_or_active_key() {
    let temp = local_state_temp_dir();
    let store = LocalKeyStore::ensure(temp.path().join("keys")).unwrap();
    let member = MemberHandle::try_from("missing@example.com").unwrap();

    assert!(store.list_kids(&member).unwrap().is_empty());
    assert_eq!(store.load_active_kid(&member).unwrap(), None);
}

/// An active marker naming a key that is not there leaves the member unusable,
/// and naming an absent member would add a directory holding no key at all.
#[test]
fn test_local_key_store_set_active_kid_requires_the_key_to_be_present() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let store = LocalKeyStore::ensure(&root).unwrap();
    let member = MemberHandle::try_from("missing@example.com").unwrap();

    let error = store.set_active_kid(&member, &test_kid()).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::NotFound);
    assert!(!root.join(member.as_str()).exists());
}

#[test]
fn test_path_like_kid_is_rejected_before_it_can_reach_the_keystore() {
    for value in ["../../outside", "/tmp/outside", "alice/bob", ""] {
        let error = Kid::try_from(value)
            .err()
            .unwrap_or_else(|| panic!("path-like kid must be rejected: {value}"));

        assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    }
}
