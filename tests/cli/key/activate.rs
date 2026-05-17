// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `key activate` command

use crate::cli::common::{cmd, generate_temp_ssh_keypair, TEST_MEMBER_HANDLE};
use secretenv_core::cli_api::test_support::helpers::kid::format_kid_display;
use secretenv_core::cli_api::test_support::storage::keystore::active::load_active_kid;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_key_activate_explicit_kid() {
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
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
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
        .env("SECRETENV_HOME", temp_dir.path())
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
    let temp_dir = TempDir::new().unwrap();
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
        .env("SECRETENV_HOME", temp_dir.path())
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
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Activate latest
    cmd()
        .arg("key")
        .arg("activate")
        .arg("--member-handle")
        .arg(member_handle)
        .env("SECRETENV_HOME", temp_dir.path())
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
        .env("SECRETENV_HOME", temp_dir.path())
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
        .env("SECRETENV_HOME", temp_dir.path())
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
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    let active_kid = load_active_kid(member_handle, &keystore_root).unwrap();
    assert_eq!(active_kid, Some(target));

    drop(ssh_temp);
}
