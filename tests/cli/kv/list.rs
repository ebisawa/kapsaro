// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `list` command

use crate::cli::common::{cmd, setup_workspace, setup_workspace_with_kv_entries};
use predicates::prelude::*;
use tempfile::TempDir;

/// Helper to create a workspace with initialized member and keys
fn setup_workspace_with_keys() -> (TempDir, TempDir, TempDir) {
    let (workspace_dir, home_dir, ssh_temp, _ssh_priv) = setup_workspace_with_kv_entries(&[
        ("DATABASE_URL", "postgres://localhost/db"),
        ("API_KEY", "secret123"),
        ("SECRET_TOKEN", "token456"),
    ]);
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
    let (workspace_dir, home_dir, ssh_temp, _ssh_priv) = setup_workspace();

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
