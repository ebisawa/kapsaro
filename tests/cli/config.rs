// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `config` command
//!
//! Tests the config command subcommands: get, set, unset, list.

use crate::cli::common::cmd;
use predicates::prelude::*;
use tempfile::TempDir;

// ============================================================================
// Help
// ============================================================================

#[test]
fn test_config_help() {
    cmd()
        .arg("config")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("config"));
}

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
        .arg("member_id")
        .arg("test@example.com")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success();

    // Get the value
    cmd()
        .arg("config")
        .arg("get")
        .arg("member_id")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("test@example.com"));
}

#[test]
fn test_config_set_and_get_ssh_identity() {
    let home_dir = TempDir::new().unwrap();

    cmd()
        .arg("config")
        .arg("set")
        .arg("ssh_identity")
        .arg("~/.ssh/id_ed25519_work")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success();

    cmd()
        .arg("config")
        .arg("get")
        .arg("ssh_identity")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("~/.ssh/id_ed25519_work"));
}

#[test]
fn test_config_set_and_get_ssh_signing_method() {
    let home_dir = TempDir::new().unwrap();

    cmd()
        .arg("config")
        .arg("set")
        .arg("ssh_signing_method")
        .arg("ssh-keygen")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success();

    cmd()
        .arg("config")
        .arg("get")
        .arg("ssh_signing_method")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("ssh-keygen"));
}

#[test]
fn test_config_set_and_get_ssh_keygen_command() {
    let home_dir = TempDir::new().unwrap();

    cmd()
        .arg("config")
        .arg("set")
        .arg("ssh_keygen_command")
        .arg("/usr/local/bin/ssh-keygen")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success();

    cmd()
        .arg("config")
        .arg("get")
        .arg("ssh_keygen_command")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("/usr/local/bin/ssh-keygen"));
}

#[test]
fn test_config_set_and_get_ssh_add_command() {
    let home_dir = TempDir::new().unwrap();

    cmd()
        .arg("config")
        .arg("set")
        .arg("ssh_add_command")
        .arg("/usr/local/bin/ssh-add")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success();

    cmd()
        .arg("config")
        .arg("get")
        .arg("ssh_add_command")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("/usr/local/bin/ssh-add"));
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
        .arg("member_id")
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
        .stdout(predicate::str::contains("member_id"));
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

// ============================================================================
// Get nonexistent key
// ============================================================================

#[test]
fn test_config_get_nonexistent_key() {
    let home_dir = TempDir::new().unwrap();

    cmd()
        .arg("config")
        .arg("get")
        .arg("member_id")
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

#[test]
fn test_config_old_ssh_key_fails() {
    let home_dir = TempDir::new().unwrap();

    cmd()
        .arg("config")
        .arg("get")
        .arg("ssh_key")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid key").or(predicate::str::contains("Valid")));
}

#[test]
fn test_config_old_ssh_signer_fails() {
    let home_dir = TempDir::new().unwrap();

    cmd()
        .arg("config")
        .arg("get")
        .arg("ssh_signer")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid key").or(predicate::str::contains("Valid")));
}

#[test]
fn test_config_old_ssh_keygen_fails() {
    let home_dir = TempDir::new().unwrap();

    cmd()
        .arg("config")
        .arg("get")
        .arg("ssh_keygen")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid key").or(predicate::str::contains("Valid")));
}

#[test]
fn test_config_old_ssh_add_fails() {
    let home_dir = TempDir::new().unwrap();

    cmd()
        .arg("config")
        .arg("get")
        .arg("ssh_add")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid key").or(predicate::str::contains("Valid")));
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
        .arg("member_id")
        .arg("test@example.com")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success();

    // Verify it exists
    cmd()
        .arg("config")
        .arg("get")
        .arg("member_id")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("test@example.com"));

    // Unset the value
    cmd()
        .arg("config")
        .arg("unset")
        .arg("member_id")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success();

    // Verify it no longer exists
    cmd()
        .arg("config")
        .arg("get")
        .arg("member_id")
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .failure();
}
