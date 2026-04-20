// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `unset` command

use crate::cli::common::{cmd, create_temp_ssh_keypair, TEST_MEMBER_ID};
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper to create a workspace with initialized member and keys
fn setup_workspace_with_keys() -> (TempDir, TempDir, TempDir, PathBuf) {
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

    // Set multiple keys
    cmd()
        .arg("set")
        .arg("KEY1")
        .arg("value1")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("set")
        .arg("KEY2")
        .arg("value2")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    (workspace_dir, home_dir, ssh_temp, ssh_priv)
}

#[test]
fn test_unset_existing_key_with_force() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_keys();

    // Unset a key in non-interactive mode
    cmd()
        .arg("unset")
        .arg("KEY1")
        .arg("--force")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Verify the key was removed
    cmd()
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("KEY2"))
        .stdout(predicate::str::contains("KEY1").not());
}

#[test]
fn test_unset_nonexistent_key() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_keys();

    // Try to unset a non-existent key
    cmd()
        .arg("unset")
        .arg("NONEXISTENT_KEY")
        .arg("--force")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_unset_non_interactive_without_force_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_keys();

    cmd()
        .arg("unset")
        .arg("KEY1")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "without --force in non-interactive mode",
        ));
}

#[test]
fn test_unset_requires_member_id_before_confirmation() {
    let workspace_dir = TempDir::new().unwrap();
    let home_dir = TempDir::new().unwrap();

    fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir.path().join("members/incoming")).unwrap();
    fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();

    cmd()
        .arg("unset")
        .arg("KEY1")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("member handle not configured")
                .and(predicate::str::contains("without --force in non-interactive mode").not()),
        );
}

#[test]
fn test_unset_with_force() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_keys();

    cmd()
        .arg("unset")
        .arg("KEY1")
        .arg("--force")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();
}
