// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `key remove` command

use crate::cli::common::{cmd, generate_temp_ssh_keypair, TEST_MEMBER_HANDLE};
use crate::cli::key::find_kid_in_member_dir;
use kapsaro_core::cli_api::test_support::helpers::kid::format_kid_display;
use kapsaro_core::cli_api::test_support::storage::keystore::active::load_active_kid;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_key_remove_non_active() {
    let temp_dir = TempDir::new().unwrap();
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
    let temp_dir = TempDir::new().unwrap();
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

    // Try to remove active key without --force (should fail)
    cmd()
        .arg("key")
        .arg("remove")
        .arg(&kid)
        .arg("--member-handle")
        .arg(member_handle)
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .failure();

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
    let temp_dir = TempDir::new().unwrap();
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
    let temp_dir = TempDir::new().unwrap();
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
    let temp_dir = TempDir::new().unwrap();
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
