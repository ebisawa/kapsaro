// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `list` command

use crate::cli::common::{
    cmd, setup_workspace, setup_workspace_with_kv_entries, tamper_kv_signature,
};
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper to create a workspace with initialized member and keys
fn setup_workspace_with_keys() -> (TempDir, TempDir, TempDir, PathBuf) {
    let (workspace_dir, home_dir, ssh_temp, ssh_priv) = setup_workspace_with_kv_entries(&[
        ("DATABASE_URL", "postgres://localhost/db"),
        ("API_KEY", "secret123"),
        ("SECRET_TOKEN", "token456"),
    ]);
    (workspace_dir, home_dir, ssh_temp, ssh_priv)
}

#[test]
fn test_list_all_keys() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_keys();

    // List all keys
    cmd()
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("DATABASE_URL"))
        .stdout(predicate::str::contains("API_KEY"))
        .stdout(predicate::str::contains("SECRET_TOKEN"));
}

#[test]
fn test_list_with_json_output() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_keys();

    // List keys with JSON output
    let output = cmd()
        .arg("list")
        .arg("--json")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        parsed["keys"],
        serde_json::json!(["API_KEY", "DATABASE_URL", "SECRET_TOKEN"])
    );
}

#[test]
fn test_list_error_when_file_not_exists() {
    let (workspace_dir, home_dir, ssh_temp, ssh_priv) = setup_workspace();

    // Try to list keys from non-existent file
    cmd()
        .arg("list")
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
fn test_list_rejects_tampered_kv_signature() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_keys();
    let kv_path = workspace_dir.path().join("secrets").join("default.kvenc");
    tamper_kv_signature(&kv_path);

    cmd()
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Signature verification failed"));
}

#[test]
fn test_list_debug_verifies_key_possession_without_printing_values() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_keys();

    cmd()
        .arg("list")
        .arg("--debug")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "[CRYPTO] key possession: verify success",
        ))
        .stdout(predicate::str::contains("postgres://localhost/db").not())
        .stdout(predicate::str::contains("secret123").not())
        .stdout(predicate::str::contains("token456").not());
}
