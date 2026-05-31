// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `unset` command

use crate::cli::common::{cmd, make_secret_home, setup_workspace_with_kv_entries};
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper to create a workspace with initialized member and keys
fn setup_workspace_with_keys() -> (TempDir, TempDir, TempDir, PathBuf) {
    setup_workspace_with_kv_entries(&[("KEY1", "value1"), ("KEY2", "value2")])
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
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Verify the key was removed
    cmd()
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
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
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
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
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unset requires --force."))
        .stderr(predicate::str::contains("Reason: non-interactive mode."));
}

#[test]
fn test_unset_requires_member_handle_before_confirmation() {
    let workspace_dir = TempDir::new().unwrap();
    let home_dir = make_secret_home();

    fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir.path().join("members/incoming")).unwrap();
    fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();

    cmd()
        .arg("unset")
        .arg("KEY1")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("member handle not configured")
                .and(predicate::str::contains("Unset requires --force.").not()),
        );
}
