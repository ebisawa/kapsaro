// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for inspect command
//!
//! Tests the inspect command with file-enc and kv-enc formats,
//! invalid inputs, and signature verification display.

use crate::cli::common::{
    assert_member_set_review_success, cmd, encrypt_file_with_member_set_review, kapsaro_std_cmd,
    set_value_with_member_set_review, setup_workspace, ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE,
    TEST_MEMBER_HANDLE,
};
use crate::test_utils::{
    build_expiring_soon_timestamp, save_active_public_key_to_workspace,
    setup_trust_store_for_workspace, update_active_private_key_expires_at,
};
use console::strip_ansi_codes;
use kapsaro_test_support::crypto_context::setup_member_key_context;
use kapsaro_test_support::fixture::setup_test_workspace;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_inspect_file_enc_shows_metadata() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Create a test file and encrypt it
    let input_file = home_dir.path().join("secret.txt");
    fs::write(&input_file, b"hello secret world").unwrap();

    let encrypted_file = home_dir.path().join("secret.txt.encrypted");

    encrypt_file_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        &input_file,
        &encrypted_file,
        TEST_MEMBER_HANDLE,
    );

    assert!(encrypted_file.exists(), "Encrypted file should exist");

    // Inspect the encrypted file
    cmd()
        .arg("inspect")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("File-Enc v7 Metadata"))
        .stdout(predicate::str::contains("Format:"))
        .stdout(predicate::str::contains("SID:"))
        .stdout(predicate::str::contains("Recipients"))
        .stdout(predicate::str::contains("Signature"));

    // Even when signature verification information is unavailable/failed,
    // embedded attestation metadata should still be inspectable.
    cmd()
        .arg("inspect")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Attestation:"));
}

#[test]
fn test_inspect_file_enc_json_output_is_structured() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let input_file = home_dir.path().join("json_secret.txt");
    fs::write(&input_file, b"json inspect data").unwrap();
    let encrypted_file = home_dir.path().join("json_secret.txt.encrypted");
    encrypt_file_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        &input_file,
        &encrypted_file,
        TEST_MEMBER_HANDLE,
    );

    let assert = cmd()
        .arg("inspect")
        .arg(&encrypted_file)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--json")
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("inspect --json should output valid JSON");

    assert_eq!(parsed["format"], "file-enc");
    assert_eq!(parsed["version"], 7);
    assert!(parsed["header"].is_object());
    assert!(parsed["wrap_data"].is_object());
    assert!(parsed["payload"].is_object());
    assert!(parsed["signature"].is_object());
    assert!(parsed["signature_verification"].is_object());
    assert_eq!(parsed["online_verification"], serde_json::Value::Null);
}

#[test]
fn test_inspect_kv_enc_shows_metadata() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Set a KV value to create an encrypted KV file
    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "DB_URL",
        "pg://host",
        Some(TEST_MEMBER_HANDLE),
        None,
    );

    let encrypted_kv = workspace_dir.path().join("secrets").join("default.kvenc");
    assert!(encrypted_kv.exists(), "Encrypted KV file should exist");

    // Inspect the KV encrypted file
    cmd()
        .arg("inspect")
        .arg(encrypted_kv.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("KV-Enc Metadata"))
        .stdout(predicate::str::contains("Header"))
        .stdout(predicate::str::contains("Wrap Data"))
        .stdout(predicate::str::contains("Entries"))
        .stdout(predicate::str::contains("Signature"));

    cmd()
        .arg("inspect")
        .arg(encrypted_kv.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Attestation:"));
}

#[test]
fn test_inspect_kv_enc_json_output_is_structured() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "DB_URL",
        "pg://host",
        Some(TEST_MEMBER_HANDLE),
        None,
    );

    let encrypted_kv = workspace_dir.path().join("secrets").join("default.kvenc");

    let assert = cmd()
        .arg("inspect")
        .arg(&encrypted_kv)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--json")
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("inspect --json should output valid JSON");

    assert_eq!(parsed["format"], "kv-enc");
    assert_eq!(parsed["version"], 1);
    assert!(parsed["header"].is_object());
    assert!(parsed["wrap_data"].is_object());
    assert!(parsed["entries"].is_array());
    assert!(parsed["summary"].is_object());
    assert!(parsed["signature_verification"].is_object());
    assert_eq!(parsed["online_verification"], serde_json::Value::Null);
}

#[test]
fn test_inspect_invalid_format_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Create a plain text file (not encrypted)
    let plain_file = home_dir.path().join("plain.txt");
    fs::write(&plain_file, "This is just plain text, not encrypted.").unwrap();

    cmd()
        .arg("inspect")
        .arg(plain_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

#[test]
fn test_inspect_nonexistent_file_fails() {
    let temp_dir = TempDir::new().unwrap();
    let nonexistent = temp_dir.path().join("does_not_exist.encrypted");

    cmd()
        .arg("inspect")
        .arg(nonexistent.to_str().unwrap())
        .assert()
        .failure();
}

#[test]
fn test_inspect_shows_signature_verification() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Create and encrypt a file
    let input_file = home_dir.path().join("secret_for_sig.txt");
    fs::write(&input_file, b"signature test data").unwrap();

    let encrypted_file = home_dir.path().join("secret_for_sig.txt.encrypted");

    encrypt_file_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        &input_file,
        &encrypted_file,
        TEST_MEMBER_HANDLE,
    );

    // Inspect should show signature verification section
    cmd()
        .arg("inspect")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature Verification"))
        .stdout(predicate::str::contains("Status:"));
}

#[test]
fn test_inspect_kv_shows_entry_count() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Set a KV value
    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "API_KEY",
        "secret123",
        Some(TEST_MEMBER_HANDLE),
        None,
    );

    let encrypted_kv = workspace_dir.path().join("secrets").join("default.kvenc");
    assert!(encrypted_kv.exists(), "Encrypted KV file should exist");

    // Inspect should show total entry count
    cmd()
        .arg("inspect")
        .arg(encrypted_kv.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Total Entries: 1"));
}

#[test]
fn test_inspect_succeeds_without_workspace_or_private_key() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let input_file = home_dir.path().join("no_private_key.txt");
    fs::write(&input_file, b"inspect without private key").unwrap();

    let encrypted_file = home_dir.path().join("no_private_key.txt.encrypted");
    encrypt_file_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        &input_file,
        &encrypted_file,
        TEST_MEMBER_HANDLE,
    );

    cmd()
        .arg("inspect")
        .arg(encrypted_file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature Verification"))
        .stdout(predicate::str::contains("Status:"));
}

#[test]
fn test_inspect_ignores_trust_store_and_strict_key_checking() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let input_file = home_dir.path().join("ignore_trust.txt");
    fs::write(&input_file, b"inspect ignores trust store").unwrap();

    let encrypted_file = home_dir.path().join("ignore_trust.txt.encrypted");
    encrypt_file_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        &input_file,
        &encrypted_file,
        TEST_MEMBER_HANDLE,
    );

    let trust_dir = home_dir.path().join("trust");
    fs::create_dir_all(&trust_dir).unwrap();
    fs::write(
        trust_dir.join(format!("{}.json", TEST_MEMBER_HANDLE)),
        "{ this is not valid trust store json",
    )
    .unwrap();

    cmd()
        .arg("inspect")
        .arg(encrypted_file.to_str().unwrap())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_STRICT_KEY_CHECKING", "no")
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature Verification"))
        .stdout(predicate::str::contains("Status:"));
}

#[test]
fn test_inspect_colors_public_key_expiry_warning_when_forced() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let ssh_pub = ssh_priv.with_extension("pub");
    fs::create_dir_all(home_dir.path().join(".ssh")).unwrap();
    fs::copy(&ssh_priv, home_dir.path().join(".ssh").join("test_ed25519")).unwrap();
    fs::copy(
        &ssh_pub,
        home_dir.path().join(".ssh").join("test_ed25519.pub"),
    )
    .unwrap();
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(home_dir.path(), TEST_MEMBER_HANDLE, &expires_at);
    save_active_public_key_to_workspace(home_dir.path(), workspace_dir.path(), TEST_MEMBER_HANDLE)
        .unwrap();

    let input_file = home_dir.path().join("inspect_warning.txt");
    fs::write(&input_file, b"inspect warning test").unwrap();

    let encrypted_file = home_dir.path().join("inspect_warning.txt.encrypted");
    encrypt_file_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        &input_file,
        &encrypted_file,
        TEST_MEMBER_HANDLE,
    );

    let assert = cmd()
        .arg("inspect")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .env("CLICOLOR_FORCE", "1")
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(
        stdout.contains("\u{1b}[33m  Warning:     \u{26a0} PublicKey for '"),
        "expected ANSI-colored inspect warning in stdout, got: {}",
        stdout
    );
    assert!(
        strip_ansi_codes(&stdout).contains("Warning:     \u{26a0} PublicKey for '"),
        "expected inspect warning text after stripping ANSI, got: {}",
        stdout
    );
}

#[test]
fn test_inspect_colors_disclosed_rotation_warning_when_forced() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    let ssh_identity = temp_dir.path().join(".ssh").join("test_ed25519");
    set_value_with_member_set_review(
        &workspace_dir,
        temp_dir.path(),
        &ssh_identity,
        "API_KEY",
        "secret123",
        Some(ALICE_MEMBER_HANDLE),
        Some("disclosed"),
    );

    fs::remove_file(
        workspace_dir
            .join("members/active")
            .join(format!("{}.json", BOB_MEMBER_HANDLE)),
    )
    .unwrap();

    let mut rewrap_cmd = kapsaro_std_cmd();
    rewrap_cmd
        .arg("rewrap")
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .env("KAPSARO_HOME", temp_dir.path())
        .env("KAPSARO_SSH_IDENTITY", &ssh_identity);
    assert_member_set_review_success(&mut rewrap_cmd);

    let encrypted_kv = workspace_dir.join("secrets").join("disclosed.kvenc");
    let assert = cmd()
        .arg("inspect")
        .arg(&encrypted_kv)
        .arg("--workspace")
        .arg(&workspace_dir)
        .env("KAPSARO_HOME", temp_dir.path())
        .env("KAPSARO_SSH_IDENTITY", &ssh_identity)
        .env("CLICOLOR_FORCE", "1")
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(
        stdout.contains(
            "\u{1b}[33m      \u{26a0} DISCLOSED \u{2014} Secret may need rotation\u{1b}[0m"
        ),
        "expected ANSI-colored disclosed warning in stdout, got: {}",
        stdout
    );
    assert!(
        strip_ansi_codes(&stdout).contains("\u{26a0} DISCLOSED \u{2014} Secret may need rotation"),
        "expected disclosed warning text after stripping ANSI, got: {}",
        stdout
    );
}
