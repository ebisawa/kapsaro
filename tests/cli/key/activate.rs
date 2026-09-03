// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `key activate` command

use crate::cli::common::{
    cmd, generate_temp_ssh_keypair, make_secret_home, save_trust_store_signed_by_active_key,
    ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE, TEST_MEMBER_HANDLE,
};
use crate::cli::key::install_secondary_member_fixture;
use kapsaro_core::test_support::helpers::kid::format_kid_display;
use kapsaro_core::test_support::storage::keystore::active::load_active_kid;
use kapsaro_test_support::fixture::setup_test_keystore_from_fixtures;
use std::fs;

#[test]
fn test_key_activate_explicit_kid() {
    let temp_dir = make_secret_home();
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

    // Activate the first kid
    let first_kid = &kids[0];
    cmd()
        .arg("key")
        .arg("activate")
        .arg(first_kid)
        .arg("--member-handle")
        .arg(member_handle)
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    // Verify active kid
    let active_kid = load_active_kid(member_handle, &keystore_root).expect("Should get active kid");
    assert_eq!(active_kid, Some(first_kid.clone()));

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_activate_latest() {
    let temp_dir = make_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Generate 2 keys (second one will be newer)
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

    std::thread::sleep(std::time::Duration::from_millis(100));

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

    // Activate latest
    cmd()
        .arg("key")
        .arg("activate")
        .arg("--member-handle")
        .arg(member_handle)
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    // Verify active kid is set
    let keystore_root = temp_dir.path().join("keys");
    let active_kid = load_active_kid(member_handle, &keystore_root).expect("Should get active kid");
    assert!(active_kid.is_some(), "Should have an active kid");

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_activate_accepts_display_kid() {
    let temp_dir = make_secret_home();
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
    let target = kids[0].clone();

    cmd()
        .arg("key")
        .arg("activate")
        .arg(format_kid_display(&target).unwrap())
        .arg("--member-handle")
        .arg(member_handle)
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    let active_kid = load_active_kid(member_handle, &keystore_root).unwrap();
    assert_eq!(active_kid, Some(target));

    drop(ssh_temp);
}

/// Activation never signs, so it reports rather than fixes a trust store that
/// still leans on the key being replaced.
#[test]
fn test_key_activate_reports_a_trust_store_signed_by_another_key() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    install_secondary_member_fixture(&home, BOB_MEMBER_HANDLE);
    let signer_kid =
        save_trust_store_signed_by_active_key(&home, ALICE_MEMBER_HANDLE, Vec::new(), Vec::new());
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .arg("--no-activate")
        .arg("--ssh-identity")
        .arg(home.path().join(".ssh").join("test_ed25519"))
        .arg("--home")
        .arg(home.path())
        .env("KAPSARO_MEMBER_HANDLE", BOB_MEMBER_HANDLE)
        .assert()
        .success();
    let member_dir = home.path().join("keys").join(ALICE_MEMBER_HANDLE);
    let rotated_kid = fs::read_dir(&member_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_str().unwrap().to_string())
        .find(|kid| kid != &signer_kid)
        .expect("a second key must exist");

    let assert = cmd()
        .arg("key")
        .arg("activate")
        .arg(&rotated_kid)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .arg("--home")
        .arg(home.path())
        .env("KAPSARO_MEMBER_HANDLE", BOB_MEMBER_HANDLE)
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(
        stderr.contains("Local trust store is still signed by kid")
            && stderr.contains("kapsaro trust resign --member-handle alice@example.com",),
        "activation must point at the command that moves the signature, got: {stderr}"
    );
}

#[test]
fn test_key_activate_with_environment_member_handle_in_multi_member_home() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    install_secondary_member_fixture(&home, BOB_MEMBER_HANDLE);
    let keystore_root = home.path().join("keys");
    let alice_kid = load_active_kid(ALICE_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .expect("Alice fixture must have an active key");
    fs::remove_file(keystore_root.join(ALICE_MEMBER_HANDLE).join("active")).unwrap();

    cmd()
        .arg("key")
        .arg("activate")
        .arg(&alice_kid)
        .arg("--home")
        .arg(home.path())
        .env("KAPSARO_MEMBER_HANDLE", ALICE_MEMBER_HANDLE)
        .assert()
        .success();

    assert_eq!(
        load_active_kid(ALICE_MEMBER_HANDLE, &keystore_root).unwrap(),
        Some(alice_kid)
    );
}
