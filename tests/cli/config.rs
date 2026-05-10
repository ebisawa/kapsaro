// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `config` command
//!
//! Tests the config command subcommands: get, set, unset, list.

use crate::cli::common::{cmd, setup_workspace, TEST_MEMBER_HANDLE};
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

// ============================================================================
// Set and Get
// ============================================================================

#[test]
fn test_config_set_and_get() {
    let home_dir = TempDir::new().unwrap();

    // Set a value
    cmd()
        .arg("config")
        .arg("set")
        .arg("member_handle")
        .arg("test@example.com")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success();

    // Get the value
    cmd()
        .arg("config")
        .arg("get")
        .arg("member_handle")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("test@example.com"));
}

#[test]
fn test_config_set_and_get_workspace() {
    let home_dir = TempDir::new().unwrap();

    cmd()
        .arg("config")
        .arg("set")
        .arg("workspace")
        .arg("~/projects/demo/.secretenv")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success();

    cmd()
        .arg("config")
        .arg("get")
        .arg("workspace")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("~/projects/demo/.secretenv"));
}

// ============================================================================
// Set and List
// ============================================================================

#[test]
fn test_config_set_and_list() {
    let home_dir = TempDir::new().unwrap();

    // Set a value
    cmd()
        .arg("config")
        .arg("set")
        .arg("member_handle")
        .arg("test@example.com")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success();

    // List all configurations
    cmd()
        .arg("config")
        .arg("list")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("member_handle"));
}

#[test]
fn test_config_list_includes_workspace() {
    let home_dir = TempDir::new().unwrap();

    cmd()
        .arg("config")
        .arg("set")
        .arg("workspace")
        .arg("/tmp/secretenv/.secretenv")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success();

    cmd()
        .arg("config")
        .arg("list")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("workspace"))
        .stdout(predicate::str::contains("/tmp/secretenv/.secretenv"));
}

#[test]
fn test_workspace_config_is_used_for_workspace_commands() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let outside_dir = TempDir::new().unwrap();

    cmd()
        .arg("config")
        .arg("set")
        .arg("workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success();

    cmd()
        .arg("member")
        .arg("list")
        .current_dir(outside_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains(TEST_MEMBER_HANDLE));
}

#[test]
fn test_config_set_creates_home_dir_if_missing() {
    let base_dir = TempDir::new().unwrap();
    let home_dir = base_dir.path().join("missing_home_dir");

    assert!(
        !home_dir.exists(),
        "Precondition: SECRETENV_HOME directory must not exist"
    );

    cmd()
        .arg("config")
        .arg("set")
        .arg("github_user")
        .arg("ebisawa")
        .env("SECRETENV_HOME", &home_dir)
        .assert()
        .success();

    assert!(home_dir.exists(), "Expected SECRETENV_HOME to be created");
    assert!(
        home_dir.join("config.toml").exists(),
        "Expected config.toml to be written"
    );
}

#[cfg(unix)]
#[test]
fn test_config_set_rejects_symlinked_lock_file() {
    use std::os::unix::fs::symlink;

    let home_dir = TempDir::new().unwrap();
    let victim = home_dir.path().join("victim.txt");
    fs::write(&victim, "original").unwrap();
    symlink(&victim, home_dir.path().join(".config.toml.lock")).unwrap();

    cmd()
        .arg("config")
        .arg("set")
        .arg("member_handle")
        .arg("test@example.com")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("symlink"));

    assert_eq!(fs::read_to_string(&victim).unwrap(), "original");
}

// ============================================================================
// Get nonexistent key
// ============================================================================

#[test]
fn test_config_get_nonexistent_key() {
    let home_dir = TempDir::new().unwrap();

    cmd()
        .arg("config")
        .arg("get")
        .arg("member_handle")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .failure();
}

// ============================================================================
// Invalid key
// ============================================================================

#[test]
fn test_config_invalid_key_fails() {
    let home_dir = TempDir::new().unwrap();

    cmd()
        .arg("config")
        .arg("get")
        .arg("invalid_key")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid key").or(predicate::str::contains("Invalid")));
}

// ============================================================================
// Unset removes value
// ============================================================================

#[test]
fn test_config_unset_removes_value() {
    let home_dir = TempDir::new().unwrap();

    // Set a value
    cmd()
        .arg("config")
        .arg("set")
        .arg("member_handle")
        .arg("test@example.com")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success();

    // Verify it exists
    cmd()
        .arg("config")
        .arg("get")
        .arg("member_handle")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("test@example.com"));

    // Unset the value
    cmd()
        .arg("config")
        .arg("unset")
        .arg("member_handle")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success();

    // Verify it no longer exists
    cmd()
        .arg("config")
        .arg("get")
        .arg("member_handle")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .failure();
}

#[test]
fn test_config_unset_removes_workspace_value() {
    let home_dir = TempDir::new().unwrap();

    cmd()
        .arg("config")
        .arg("set")
        .arg("workspace")
        .arg("/tmp/secretenv/.secretenv")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success();

    cmd()
        .arg("config")
        .arg("unset")
        .arg("workspace")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success();

    cmd()
        .arg("config")
        .arg("get")
        .arg("workspace")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .failure();
}
