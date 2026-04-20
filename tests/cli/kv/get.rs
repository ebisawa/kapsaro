// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `get` command

use crate::cli::common::{cmd, create_temp_ssh_keypair, TEST_MEMBER_ID};
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper to create a workspace with initialized member and a key
fn setup_workspace_with_key() -> (TempDir, TempDir, TempDir, PathBuf) {
    let workspace_dir = TempDir::new().unwrap();
    let home_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = create_temp_ssh_keypair();

    // Create workspace structure
    fs::create_dir_all(workspace_dir.path().join("members")).unwrap();
    fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();

    // Run init to register member
    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Set a key
    cmd()
        .arg("set")
        .arg("TEST_KEY")
        .arg("test_value")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    (workspace_dir, home_dir, ssh_temp, ssh_priv)
}

fn setup_workspace_with_multiple_keys() -> (TempDir, TempDir, TempDir, PathBuf) {
    let (workspace_dir, home_dir, ssh_temp, ssh_priv) = setup_workspace_with_key();

    cmd()
        .arg("set")
        .arg("ANOTHER_KEY")
        .arg("another_value")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    (workspace_dir, home_dir, ssh_temp, ssh_priv)
}

#[test]
fn test_get_existing_key() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_key();

    // Get the key (use same SSH key for decryption)
    cmd()
        .arg("get")
        .arg("TEST_KEY")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("test_value"));
}

#[test]
fn test_get_nonexistent_key() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_key();

    // Try to get a non-existent key
    cmd()
        .arg("get")
        .arg("NONEXISTENT_KEY")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_get_with_json_output() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_key();

    // Get the key with JSON output
    cmd()
        .arg("get")
        .arg("TEST_KEY")
        .arg("--json")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("\"TEST_KEY\""))
        .stdout(predicate::str::contains("\"test_value\""));
}

#[test]
fn test_get_error_when_file_not_exists() {
    let workspace_dir = TempDir::new().unwrap();
    let home_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = create_temp_ssh_keypair();

    // Create workspace structure
    fs::create_dir_all(workspace_dir.path().join("members")).unwrap();
    fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();

    // Run init to register member
    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Try to get a key from non-existent file
    cmd()
        .arg("get")
        .arg("TEST_KEY")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));

    drop(ssh_temp);
}

#[test]
fn test_get_all() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_multiple_keys();

    cmd()
        .arg("get")
        .arg("--all")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("test_value"))
        .stdout(predicate::str::contains("another_value"));
}

#[test]
fn test_get_all_verbose_logs_public_key_verification_contexts() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_key();

    cmd()
        .arg("get")
        .arg("--all")
        .arg("--verbose")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("(keystore sibling public.json, "))
        .stdout(predicate::str::contains("(embedded signer_pub, "))
        .stdout(predicate::str::contains("(active member/read trust, "))
        .stdout(predicate::str::contains("(workspace active member recipient validation, ").not());
}

#[test]
fn test_get_all_with_key() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_multiple_keys();

    cmd()
        .arg("get")
        .arg("--all")
        .arg("--with-key")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("ANOTHER_KEY=\"another_value\""))
        .stdout(predicate::str::contains("TEST_KEY=\"test_value\""));
}

#[test]
fn test_get_with_key_format() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_key();

    cmd()
        .arg("get")
        .arg("--with-key")
        .arg("TEST_KEY")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("TEST_KEY=\"test_value\""));
}

#[test]
fn test_get_all_with_key_arg_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_key();

    cmd()
        .arg("get")
        .arg("--all")
        .arg("TEST_KEY")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

#[test]
fn test_get_without_key_and_all_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_key();

    cmd()
        .arg("get")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

#[test]
fn test_get_all_json() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_multiple_keys();

    cmd()
        .arg("get")
        .arg("--all")
        .arg("--json")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("\"ANOTHER_KEY\""))
        .stdout(predicate::str::contains("\"TEST_KEY\""))
        .stdout(predicate::str::contains("\"test_value\""))
        .stdout(predicate::str::contains("\"another_value\""));
}
