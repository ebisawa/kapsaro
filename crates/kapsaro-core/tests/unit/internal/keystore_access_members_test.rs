// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Member enumeration tests for the anchored keystore capability.
//! Covers empty, freshly created and multi-member keystore roots.

use crate::io::keystore::access::KeystoreAccess;
use crate::model::identity::MemberHandle;
use crate::test_utils::local_state_temp_dir;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_list_members_empty() {
    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path();

    let access = KeystoreAccess::create(keystore_root).unwrap();
    let result = access.list_members().unwrap();
    assert_eq!(result, Vec::<MemberHandle>::new());
}

#[test]
fn test_list_members_multiple_members() {
    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path();

    // Create member directories
    fs::create_dir_all(keystore_root.join("alice@example.com")).unwrap();
    fs::create_dir_all(keystore_root.join("bob@example.com")).unwrap();
    fs::create_dir_all(keystore_root.join("charlie@example.com")).unwrap();

    let access = KeystoreAccess::open(keystore_root).unwrap();
    let result = access
        .list_members()
        .unwrap()
        .into_iter()
        .map(MemberHandle::into_string)
        .collect::<Vec<_>>();
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
fn test_list_members_new_keystore() {
    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path().join("nonexistent");

    let access = KeystoreAccess::create(&keystore_root).unwrap();
    let result = access.list_members().unwrap();
    assert_eq!(result, Vec::<MemberHandle>::new());
}

/// A symlink under a name no member could carry is never read as a member, so
/// enumeration passes over it and the diagnostic listing names it instead.
#[cfg(unix)]
#[test]
fn test_symlinked_root_entry_is_listed_as_ignored() {
    use std::os::unix::fs::symlink;

    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path();
    let outside = TempDir::new().unwrap();
    fs::create_dir_all(keystore_root.join("alice@example.com")).unwrap();
    symlink(outside.path(), keystore_root.join("linked outside")).unwrap();

    let access = KeystoreAccess::open(keystore_root).unwrap();

    assert_eq!(
        access
            .list_members()
            .unwrap()
            .into_iter()
            .map(MemberHandle::into_string)
            .collect::<Vec<_>>(),
        vec!["alice@example.com".to_string()]
    );
    assert_eq!(
        access.list_ignored_root_entries().unwrap(),
        vec!["linked outside".to_string()]
    );
}

/// A symlink is never read as a member, so enumeration passes over it and
/// returns the members that are really there. Refusing the whole root instead
/// would let one link nobody asked about hide every member behind it.
#[cfg(unix)]
#[test]
fn test_member_named_symlink_is_skipped_by_enumeration() {
    use std::os::unix::fs::symlink;

    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path();
    let outside = TempDir::new().unwrap();
    fs::create_dir_all(keystore_root.join("alice@example.com")).unwrap();
    symlink(outside.path(), keystore_root.join("bob@example.com")).unwrap();

    let access = KeystoreAccess::open(keystore_root).unwrap();
    let members = access.list_members().unwrap();

    assert_eq!(
        members,
        vec![MemberHandle::try_from("alice@example.com").unwrap()]
    );
}

/// Internal staging names are not canonical member entries.
#[test]
fn test_leftover_staging_entry_is_ignored_by_member_readers() {
    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path();
    fs::create_dir_all(keystore_root.join(".tmp-3f2504e0-4f89-41d3-9a0c-0305e82c3301")).unwrap();

    let access = KeystoreAccess::open(keystore_root).unwrap();
    assert!(access.list_members().unwrap().is_empty());
    assert!(access.list_ignored_root_entries().unwrap().is_empty());
}

/// The rejection keys on the staging name shape, not on the leading dot, so an
/// ordinary hidden entry stays ignored.
#[test]
fn test_unrelated_hidden_root_entry_stays_ignored() {
    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path();
    fs::write(keystore_root.join(".DS_Store"), "metadata").unwrap();
    fs::write(keystore_root.join(".alice@example.com.tmp.stale"), "note").unwrap();

    let access = KeystoreAccess::open(keystore_root).unwrap();

    assert_eq!(access.list_members().unwrap(), Vec::<MemberHandle>::new());
    assert_eq!(
        access.list_ignored_root_entries().unwrap(),
        Vec::<String>::new()
    );
}
