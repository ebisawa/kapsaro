// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `key remove` command

use crate::cli::common::{
    cmd, generate_temp_ssh_keypair, save_trust_store_signed_by_active_key, setup_secret_home,
    ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE, TEST_MEMBER_HANDLE, TRUST_STORE_STORED_AT,
};
use crate::cli::key::{find_kid_in_member_dir, install_secondary_member_fixture};
use kapsaro_core::test_support::helpers::kid::format_kid_display;
use kapsaro_core::test_support::storage::keystore::active::load_active_kid;
#[cfg(unix)]
use kapsaro_test_support::fixture::ensure_local_state_dir;
use kapsaro_test_support::fixture::setup_test_keystore_from_fixtures;
use predicates::prelude::*;
use std::fs;

#[cfg(unix)]
use std::os::unix::fs::symlink;

/// Removal reaches the keystore behind a symlinked local state root, so the key
/// selected through the link is the one that is deleted.
#[cfg(unix)]
#[test]
fn test_key_remove_deletes_through_a_home_symlink() {
    let temp = setup_secret_home();
    let real_home = temp.path().join("real-home");
    let selected_home = temp.path().join("selected-home");
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    ensure_local_state_dir(&real_home);
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("-i")
        .arg(&ssh_priv)
        .env("KAPSARO_HOME", &real_home)
        .assert()
        .success();
    let member_dir = real_home.join("keys").join(TEST_MEMBER_HANDLE);
    let kid = find_kid_in_member_dir(&member_dir);
    symlink(&real_home, &selected_home).unwrap();

    cmd()
        .arg("key")
        .arg("remove")
        .arg(&kid)
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--force")
        .arg("--home")
        .arg(&selected_home)
        .assert()
        .success();

    assert!(!member_dir.join(kid).exists());
    drop(ssh_temp);
}

#[test]
fn test_key_remove_non_active() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Generate 2 keys
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .arg("--no-activate")
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    // Get the kids
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kids: Vec<_> = fs::read_dir(&member_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_str().unwrap().to_string())
        .collect();

    assert_eq!(kids.len(), 2, "Should have 2 kids");

    // Find the active kid and the non-active kid
    let active_kid = load_active_kid(member_handle, &keystore_root)
        .expect("Should get active kid")
        .unwrap();
    let non_active_kid = kids.iter().find(|k| k != &&active_kid).unwrap();

    // Remove the non-active kid
    cmd()
        .arg("key")
        .arg("remove")
        .arg(non_active_kid)
        .arg("--member-handle")
        .arg(member_handle)
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    // Verify kid was removed
    let kids_after: Vec<_> = fs::read_dir(&member_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_str().unwrap().to_string())
        .collect();

    assert_eq!(kids_after.len(), 1, "Should have 1 kid after removal");

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_remove_active_without_force() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Generate a key
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    // Get the kid
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);
    install_secondary_member_fixture(&temp_dir, BOB_MEMBER_HANDLE);

    // Try to remove active key without --force (should fail)
    cmd()
        .arg("key")
        .arg("remove")
        .arg(&kid)
        .arg("--member-handle")
        .arg(member_handle)
        .env("KAPSARO_HOME", temp_dir.path())
        .env("KAPSARO_MEMBER_HANDLE", BOB_MEMBER_HANDLE)
        .assert()
        .failure()
        .stderr(predicate::str::contains(format!(
            "kapsaro key activate <other-kid> --member-handle {member_handle}"
        )));

    // Verify kid still exists
    let private_key_path = member_dir.join(&kid).join("private.json");
    assert!(
        private_key_path.exists(),
        "Active key should not be removed without --force"
    );

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_remove_active_with_force() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Generate a key
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    // Get the kid
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);

    // Remove active key with --force
    cmd()
        .arg("key")
        .arg("remove")
        .arg(&kid)
        .arg("--member-handle")
        .arg(member_handle)
        .arg("--force")
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    // Verify kid was removed
    let private_key_path = member_dir.join(&kid).join("private.json");
    assert!(
        !private_key_path.exists(),
        "Key should be removed with --force"
    );

    // Verify active is cleared
    let active_kid = load_active_kid(member_handle, &keystore_root).expect("Should get active kid");
    assert!(active_kid.is_none(), "Active kid should be cleared");

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_remove_accepts_unique_prefix_without_member_handle() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    let member_handle = TEST_MEMBER_HANDLE;

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .arg("--no-activate")
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kids: Vec<_> = fs::read_dir(&member_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_str().unwrap().to_string())
        .collect();
    let active_kid = load_active_kid(member_handle, &keystore_root)
        .unwrap()
        .unwrap();
    let non_active_kid = kids.into_iter().find(|kid| kid != &active_kid).unwrap();

    cmd()
        .arg("key")
        .arg("remove")
        .arg(&non_active_kid[..4])
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    assert!(!member_dir.join(&non_active_kid).exists());

    drop(ssh_temp);
}

#[test]
fn test_key_remove_accepts_display_kid() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    let member_handle = TEST_MEMBER_HANDLE;

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .arg("--no-activate")
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kids: Vec<_> = fs::read_dir(&member_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_str().unwrap().to_string())
        .collect();
    let active_kid = load_active_kid(member_handle, &keystore_root)
        .unwrap()
        .unwrap();
    let non_active_kid = kids.into_iter().find(|kid| kid != &active_kid).unwrap();

    cmd()
        .arg("key")
        .arg("remove")
        .arg(format_kid_display(&non_active_kid).unwrap())
        .arg("--member-handle")
        .arg(member_handle)
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    assert!(!member_dir.join(&non_active_kid).exists());

    drop(ssh_temp);
}

/// The last key able to sign the local trust store is not removable by
/// accident: losing it makes every stored approval unverifiable.
#[test]
fn test_key_remove_refuses_the_only_trust_store_signer() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let signer_kid = save_trust_store_signed_by_active_key(
        &home,
        ALICE_MEMBER_HANDLE,
        TRUST_STORE_STORED_AT,
        Vec::new(),
        Vec::new(),
    );

    cmd()
        .arg("key")
        .arg("remove")
        .arg(&signer_kid)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .arg("--home")
        .arg(home.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "kapsaro key activate <other-kid> --member-handle alice@example.com",
        ));

    assert!(home
        .path()
        .join("keys")
        .join(ALICE_MEMBER_HANDLE)
        .join(&signer_kid)
        .exists());
}

/// A trust store written in a later format still carries approvals and still
/// names a signer, this build just cannot read which. The removal stops instead
/// of dropping a key those approvals may depend on.
#[test]
fn test_key_remove_refuses_a_trust_store_it_cannot_read() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let signer_kid = save_trust_store_signed_by_active_key(
        &home,
        ALICE_MEMBER_HANDLE,
        TRUST_STORE_STORED_AT,
        Vec::new(),
        Vec::new(),
    );
    save_later_trust_store_format(home.path(), ALICE_MEMBER_HANDLE);

    cmd()
        .arg("key")
        .arg("remove")
        .arg(&signer_kid)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .arg("--home")
        .arg(home.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("must be reset"));

    assert!(home
        .path()
        .join("keys")
        .join(ALICE_MEMBER_HANDLE)
        .join(&signer_kid)
        .exists());
}

/// Save the stored trust store back as a document from a later format.
fn save_later_trust_store_format(home: &std::path::Path, owner_handle: &str) {
    let path = home.join("trust").join(format!("{owner_handle}.json"));
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    document["protected"]["format"] =
        serde_json::Value::String("kapsaro:format:local-trust@2".to_string());
    fs::write(&path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
}

#[test]
fn test_key_remove_forced_reports_how_to_restore_the_trust_store_signer() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    install_secondary_member_fixture(&home, BOB_MEMBER_HANDLE);
    let signer_kid = save_trust_store_signed_by_active_key(
        &home,
        ALICE_MEMBER_HANDLE,
        TRUST_STORE_STORED_AT,
        Vec::new(),
        Vec::new(),
    );

    let assert = cmd()
        .arg("key")
        .arg("remove")
        .arg(&signer_kid)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .arg("--force")
        .arg("--home")
        .arg(home.path())
        .env("KAPSARO_MEMBER_HANDLE", BOB_MEMBER_HANDLE)
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(
        stderr.contains("kapsaro trust resign --member-handle alice@example.com")
            && stderr.contains("public.json"),
        "a forced removal must name the way back, got: {stderr}"
    );
    assert!(!home
        .path()
        .join("keys")
        .join(ALICE_MEMBER_HANDLE)
        .join(&signer_kid)
        .exists());
}

#[test]
fn test_key_remove_other_member_kid_with_environment_member_handle_fails() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    install_secondary_member_fixture(&home, BOB_MEMBER_HANDLE);
    let keystore_root = home.path().join("keys");
    let bob_kid = load_active_kid(BOB_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .expect("Bob fixture must have an active key");
    let bob_key_dir = keystore_root.join(BOB_MEMBER_HANDLE).join(&bob_kid);

    cmd()
        .arg("key")
        .arg("remove")
        .arg(&bob_kid)
        .arg("--force")
        .arg("--home")
        .arg(home.path())
        .env("KAPSARO_MEMBER_HANDLE", ALICE_MEMBER_HANDLE)
        .assert()
        .failure();

    assert!(bob_key_dir.exists(), "Bob's key must remain untouched");
}
