// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `list` command

#[cfg(unix)]
use crate::cli::common::artifact::setup_unapproved_kv_signer_read_fixture;
use crate::cli::common::{
    cmd, setup_unapproved_kv_read_fixture, setup_workspace, setup_workspace_with_kv_entries,
    tamper_kv_signature,
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
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("DATABASE_URL"))
        .stdout(predicate::str::contains("API_KEY"))
        .stdout(predicate::str::contains("SECRET_TOKEN"));
}

#[cfg(unix)]
#[test]
fn test_list_unknown_recipient_non_interactive_error() {
    let fixture = setup_unapproved_kv_read_fixture();

    cmd()
        .arg("list")
        .arg("--member-handle")
        .arg(crate::cli::common::ALICE_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(&fixture.workspace)
        .env("KAPSARO_HOME", fixture.home.path())
        .env("KAPSARO_SSH_IDENTITY", &fixture.ssh_identity)
        .env("KAPSARO_STRICT_KEY_CHECKING", "yes")
        .assert()
        .failure()
        .stdout(predicate::str::contains("SHOULD_NOT_PRINT").not())
        .stderr(predicate::str::contains(
            "Unknown recipient kid requires approval",
        ))
        .stderr(predicate::str::contains(fixture.unapproved_member_handle))
        .stderr(predicate::str::contains(&fixture.unapproved_kid))
        .stderr(predicate::str::contains("Interactive confirmation requires a terminal").not());

    assert!(!fixture.trust_store_path.exists());
}

#[cfg(unix)]
#[test]
fn test_list_skips_known_signer_review_when_strict_checking_is_disabled() {
    let fixture = setup_unapproved_kv_signer_read_fixture();

    cmd()
        .arg("list")
        .arg("--member-handle")
        .arg(crate::cli::common::ALICE_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(&fixture.workspace)
        .env("KAPSARO_HOME", fixture.home.path())
        .env("KAPSARO_SSH_IDENTITY", &fixture.ssh_identity)
        .env("KAPSARO_STRICT_KEY_CHECKING", "no")
        .assert()
        .success()
        .stdout(predicate::str::contains("SHOULD_NOT_PRINT"))
        .stderr(predicate::str::contains("Approve this key?").not());

    assert!(!fixture.trust_store_path.exists());
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
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
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
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
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
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
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
        .env("KAPSARO_HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "[CRYPTO] key possession: verify success",
        ))
        .stdout(predicate::str::contains("postgres://localhost/db").not())
        .stdout(predicate::str::contains("secret123").not())
        .stdout(predicate::str::contains("token456").not());
}
