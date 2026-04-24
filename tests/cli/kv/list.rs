// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `list` command

use crate::cli::common::{cmd, generate_temp_ssh_keypair, TEST_MEMBER_ID};
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Helper to create a workspace with initialized member and keys
fn setup_workspace_with_keys() -> (TempDir, TempDir, TempDir) {
    let workspace_dir = TempDir::new().unwrap();
    let home_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

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

    // Set multiple keys
    cmd()
        .arg("set")
        .arg("DATABASE_URL")
        .arg("postgres://localhost/db")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("set")
        .arg("API_KEY")
        .arg("secret123")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("set")
        .arg("SECRET_TOKEN")
        .arg("token456")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    (workspace_dir, home_dir, ssh_temp)
}

#[test]
fn test_list_all_keys() {
    let (workspace_dir, home_dir, _ssh_temp) = setup_workspace_with_keys();

    // List all keys
    cmd()
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("DATABASE_URL"))
        .stdout(predicate::str::contains("API_KEY"))
        .stdout(predicate::str::contains("SECRET_TOKEN"));
}

#[test]
fn test_list_with_json_output() {
    let (workspace_dir, home_dir, _ssh_temp) = setup_workspace_with_keys();

    // List keys with JSON output
    cmd()
        .arg("list")
        .arg("--json")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("\"keys\""))
        .stdout(predicate::str::contains("DATABASE_URL"))
        .stdout(predicate::str::contains("API_KEY"))
        .stdout(predicate::str::contains("SECRET_TOKEN"));
}

#[test]
fn test_list_error_when_file_not_exists() {
    let workspace_dir = TempDir::new().unwrap();
    let home_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

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

    // Try to list keys from non-existent file
    cmd()
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));

    drop(ssh_temp);
}
