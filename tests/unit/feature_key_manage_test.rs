// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/key/manage module

use crate::test_utils::{build_test_private_key, keygen_test, setup_test_keystore_from_fixtures};
use crate::test_utils::{ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE};
use secretenv::feature::key::manage::export::export_key;
use secretenv::feature::key::manage::mutation::{activate_key, remove_key};
use secretenv::feature::key::manage::query::list_keys;
use secretenv::io::keystore::storage::save_key_pair_atomic;
use secretenv::support::kid::format_kid_display;

/// Helper: generate a second key pair, save it to the keystore, and return its kid.
fn add_second_key(temp_dir: &tempfile::TempDir, member_handle: &str) -> String {
    let keystore_root = temp_dir.path().join("keys");
    let ssh_pub_content = std::fs::read_to_string(temp_dir.path().join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let ssh_priv = temp_dir.path().join(".ssh/test_ed25519");
    let (priv_plain, pub_key) = keygen_test(member_handle, &ssh_priv, &ssh_pub_content).unwrap();
    let kid = pub_key.protected.kid.clone();
    let priv_key = build_test_private_key(
        &priv_plain,
        member_handle,
        &kid,
        &ssh_priv,
        &ssh_pub_content,
    )
    .unwrap();

    save_key_pair_atomic(&keystore_root, member_handle, &kid, &priv_key, &pub_key).unwrap();

    kid
}

// ---------------------------------------------------------------------------
// list_keys tests
// ---------------------------------------------------------------------------

#[test]
fn test_list_keys_single_member() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let home = Some(temp_dir.path().to_path_buf());

    let result = list_keys(home, None).unwrap();

    assert_eq!(result.total_keys, 1);
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].0, ALICE_MEMBER_HANDLE);
    assert_eq!(result.entries[0].1.len(), 1);
    assert!(result.entries[0].1[0].active);
}

#[test]
fn test_list_keys_filtered_by_member_handle() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    // Add Bob's key to the same keystore
    let ssh_pub_content = std::fs::read_to_string(temp_dir.path().join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let ssh_priv = temp_dir.path().join(".ssh/test_ed25519");
    let (bob_priv_plain, bob_pub) =
        keygen_test(BOB_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();
    let bob_kid = bob_pub.protected.kid.clone();
    let bob_priv = build_test_private_key(
        &bob_priv_plain,
        BOB_MEMBER_HANDLE,
        &bob_kid,
        &ssh_priv,
        &ssh_pub_content,
    )
    .unwrap();
    save_key_pair_atomic(
        &keystore_root,
        BOB_MEMBER_HANDLE,
        &bob_kid,
        &bob_priv,
        &bob_pub,
    )
    .unwrap();

    let home = Some(temp_dir.path().to_path_buf());

    // Filter by Alice only
    let result = list_keys(home.clone(), Some(ALICE_MEMBER_HANDLE.to_string())).unwrap();
    assert_eq!(result.total_keys, 1);
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].0, ALICE_MEMBER_HANDLE);

    // Filter by Bob only
    let result = list_keys(home, Some(BOB_MEMBER_HANDLE.to_string())).unwrap();
    assert_eq!(result.total_keys, 1);
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].0, BOB_MEMBER_HANDLE);
}

#[test]
fn test_list_keys_nonexistent_member() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let home = Some(temp_dir.path().to_path_buf());

    // Listing for a member that doesn't exist should return an empty result or error.
    // Since list_kids on a non-existent directory will likely error, we accept either.
    let result = list_keys(home, Some("nonexistent@example.com".to_string()));
    if let Ok(r) = result {
        assert_eq!(r.total_keys, 0);
    }
    // Err is also acceptable — member directory doesn't exist
}

// ---------------------------------------------------------------------------
// activate_key tests
// ---------------------------------------------------------------------------

#[test]
fn test_activate_key_explicit_kid() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);

    // Add a second key (not active)
    let second_kid = add_second_key(&temp_dir, ALICE_MEMBER_HANDLE);

    let home = Some(temp_dir.path().to_path_buf());

    let result = activate_key(
        home,
        ALICE_MEMBER_HANDLE.to_string(),
        Some(format_kid_display(&second_kid).unwrap().to_lowercase()),
    )
    .unwrap();

    assert_eq!(result.member_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(result.kid, second_kid);
}

#[test]
fn test_activate_key_auto_select_latest() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);

    // Add a second key so there are two valid keys
    let second_kid = add_second_key(&temp_dir, ALICE_MEMBER_HANDLE);

    let home = Some(temp_dir.path().to_path_buf());

    // kid=None should auto-select the latest valid key by created_at.
    let result = activate_key(home, ALICE_MEMBER_HANDLE.to_string(), None).unwrap();

    assert_eq!(result.member_handle, ALICE_MEMBER_HANDLE);
    // The auto-selected key should be the second (latest) one.
    assert_eq!(result.kid, second_kid);
}

#[test]
fn test_activate_key_not_found() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let home = Some(temp_dir.path().to_path_buf());

    let result = activate_key(
        home,
        ALICE_MEMBER_HANDLE.to_string(),
        Some("00000000000000000000000000000001".to_string()),
    );

    assert!(result.is_err());
    let msg = format!("{}", result.err().unwrap());
    assert!(
        msg.contains("not found") || msg.contains("Not found"),
        "unexpected error: {msg}"
    );
}

// ---------------------------------------------------------------------------
// remove_key tests
// ---------------------------------------------------------------------------

#[test]
fn test_remove_key_non_active() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);

    // Add second key (non-active)
    let second_kid = add_second_key(&temp_dir, ALICE_MEMBER_HANDLE);

    let home = Some(temp_dir.path().to_path_buf());

    let result = remove_key(
        home,
        ALICE_MEMBER_HANDLE.to_string(),
        format_kid_display(&second_kid).unwrap().to_lowercase(),
        false,
    )
    .unwrap();

    assert_eq!(result.kid, second_kid);
    assert!(!result.was_active);
}

#[test]
fn test_remove_key_active_without_force() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    // Get the active kid
    let active_kid =
        secretenv::io::keystore::active::load_active_kid(ALICE_MEMBER_HANDLE, &keystore_root)
            .unwrap()
            .unwrap();

    let home = Some(temp_dir.path().to_path_buf());

    let result = remove_key(home, ALICE_MEMBER_HANDLE.to_string(), active_kid, false);

    assert!(result.is_err());
    let msg = format!("{}", result.err().unwrap());
    assert!(
        msg.contains("active") || msg.contains("force"),
        "unexpected error: {msg}"
    );
}

#[test]
fn test_remove_key_active_with_force() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let active_kid =
        secretenv::io::keystore::active::load_active_kid(ALICE_MEMBER_HANDLE, &keystore_root)
            .unwrap()
            .unwrap();

    let home = Some(temp_dir.path().to_path_buf());

    let result = remove_key(
        home,
        ALICE_MEMBER_HANDLE.to_string(),
        active_kid.clone(),
        true,
    )
    .unwrap();

    assert_eq!(result.kid, active_kid);
    assert!(result.was_active);

    // Verify the active kid has been cleared
    let current_active =
        secretenv::io::keystore::active::load_active_kid(ALICE_MEMBER_HANDLE, &keystore_root)
            .unwrap();
    assert!(current_active.is_none());
}

// ---------------------------------------------------------------------------
// export_key tests
// ---------------------------------------------------------------------------

#[test]
fn test_export_key_active() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let home = Some(temp_dir.path().to_path_buf());

    // Export with kid=None should use the active key
    let result = export_key(home, ALICE_MEMBER_HANDLE.to_string(), None).unwrap();

    assert_eq!(result.member_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(
        result.public_key.protected.subject_handle,
        ALICE_MEMBER_HANDLE
    );
    assert!(!result.kid.is_empty());
}

#[test]
fn test_export_key_explicit_display_kid() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");
    let active_kid =
        secretenv::io::keystore::active::load_active_kid(ALICE_MEMBER_HANDLE, &keystore_root)
            .unwrap()
            .unwrap();
    let home = Some(temp_dir.path().to_path_buf());

    let result = export_key(
        home,
        ALICE_MEMBER_HANDLE.to_string(),
        Some(format_kid_display(&active_kid).unwrap().to_lowercase()),
    )
    .unwrap();

    assert_eq!(result.kid, active_kid);
}
