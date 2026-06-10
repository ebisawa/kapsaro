// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `get` command

use crate::cli::common::{
    cmd, setup_workspace, setup_workspace_with_kv_entries, tamper_kv_signature, TEST_MEMBER_HANDLE,
};
use kapsaro_core::cli_api::presentation::kid::format_kid_display;
use kapsaro_core::cli_api::test_support::helpers::kid::format_kid_half_display;
use kapsaro_core::cli_api::test_support::storage::keystore::storage::list_kids;
use predicates::prelude::*;
use tempfile::TempDir;

/// Helper to create a workspace with initialized member and a key
fn setup_workspace_with_key() -> (TempDir, TempDir, TempDir, std::path::PathBuf) {
    setup_workspace_with_kv_entries(&[("TEST_KEY", "test_value")])
}

fn setup_workspace_with_multiple_keys() -> (TempDir, TempDir, TempDir, std::path::PathBuf) {
    setup_workspace_with_kv_entries(&[("TEST_KEY", "test_value"), ("ANOTHER_KEY", "another_value")])
}

fn active_test_kid(home_dir: &TempDir) -> String {
    list_kids(&home_dir.path().join("keys"), TEST_MEMBER_HANDLE)
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
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
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("test_value"));
}

#[test]
fn test_get_rejects_tampered_kv_signature() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_key();
    let kv_path = workspace_dir.path().join("secrets").join("default.kvenc");
    tamper_kv_signature(&kv_path);

    cmd()
        .arg("get")
        .arg("TEST_KEY")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Signature verification failed"));
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
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_get_with_json_output() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_key();

    // Get the key with JSON output
    let output = cmd()
        .arg("get")
        .arg("TEST_KEY")
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
    assert_eq!(parsed["values"]["TEST_KEY"], "test_value");
}

#[test]
fn test_get_error_when_file_not_exists() {
    let (workspace_dir, home_dir, ssh_temp, ssh_priv) = setup_workspace();

    // Try to get a key from non-existent file
    cmd()
        .arg("get")
        .arg("TEST_KEY")
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
fn test_get_all() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_multiple_keys();

    cmd()
        .arg("get")
        .arg("--all")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("test_value"))
        .stdout(predicate::str::contains("another_value"));
}

#[test]
fn test_get_all_debug_logs_public_key_verification_contexts() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_key();

    cmd()
        .arg("get")
        .arg("--all")
        .arg("--debug")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("[CLI] command=get"))
        .stdout(predicate::str::contains("[CTX] paths:"))
        .stdout(predicate::str::contains("[TRUST] read gate:"))
        .stdout(predicate::str::contains("(keystore sibling public.json, "))
        .stdout(predicate::str::contains("(embedded signer_pub, "))
        .stdout(predicate::str::contains("(active member/read trust, "))
        .stdout(predicate::str::contains("(workspace active member recipient validation, ").not());
}

#[test]
fn test_get_all_debug_uses_half_kid_for_high_frequency_traces() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_key();
    let kid = active_test_kid(&home_dir);
    let kid_full = format_kid_display(&kid).unwrap();
    let kid_half = format_kid_half_display(&kid).unwrap();

    cmd()
        .arg("get")
        .arg("--all")
        .arg("--debug")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "[CRYPTO] load_crypto_context: resolved kid={kid_full}"
        )))
        .stdout(predicate::str::contains(format!(
            "[VERIFY] Ed25519: verify_artifact_bytes (kid: {kid_half})"
        )))
        .stdout(
            predicate::str::contains(format!(
                "[VERIFY] Ed25519: verify_artifact_bytes (kid: {kid_full})"
            ))
            .not(),
        )
        .stdout(predicate::str::contains(format!(
            "[CRYPTO] HPKE: unwrap_master_key_from_item: open_base (kid: {kid_half})"
        )))
        .stdout(
            predicate::str::contains(format!(
                "[CRYPTO] HPKE: unwrap_master_key_from_item: open_base (kid: {kid_full})"
            ))
            .not(),
        )
        .stdout(predicate::str::contains(format!(
            "[CRYPTO] SSH: sign_sshsig (kid: {kid_half})"
        )))
        .stdout(
            predicate::str::contains(format!("[CRYPTO] SSH: sign_sshsig (kid: {kid_full})")).not(),
        )
        .stdout(predicate::str::contains(format!(
            "[CRYPTO] HKDF-SHA256: private key enc key derivation (kid: {kid_half})"
        )))
        .stdout(
            predicate::str::contains(format!(
                "[CRYPTO] HKDF-SHA256: private key enc key derivation (kid: {kid_full})"
            ))
            .not(),
        );
}

#[test]
fn test_get_all_verbose_does_not_log_public_key_verification_contexts() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_key();

    cmd()
        .arg("get")
        .arg("--all")
        .arg("--verbose")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("[CLI] command=get").not())
        .stdout(predicate::str::contains("[CTX] paths:").not())
        .stdout(predicate::str::contains("[TRUST] read gate:").not())
        .stdout(predicate::str::contains("(keystore sibling public.json, ").not())
        .stdout(predicate::str::contains("(embedded signer_pub, ").not())
        .stdout(predicate::str::contains("(active member/read trust, ").not());
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
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
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
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
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
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
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
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

#[test]
fn test_get_all_json() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_multiple_keys();

    let output = cmd()
        .arg("get")
        .arg("--all")
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
    assert_eq!(parsed["values"]["TEST_KEY"], "test_value");
    assert_eq!(parsed["values"]["ANOTHER_KEY"], "another_value");
}
