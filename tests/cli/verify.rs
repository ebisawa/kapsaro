// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for signature verification via inspect command
//!
//! Verifies that the inspect command correctly displays signature verification
//! results for file-enc and kv-enc formats, and properly detects tampered files.

use crate::cli::common::{cmd, setup_workspace, TEST_MEMBER_ID};
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_verify_file_enc_valid_signature() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Create a test file and encrypt it
    let input_file = home_dir.path().join("verify_test.bin");
    fs::write(&input_file, b"binary content for verification").unwrap();

    let encrypted_file = home_dir.path().join("verify_test.bin.encrypted");

    cmd()
        .arg("encrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--member-handle")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    assert!(encrypted_file.exists(), "Encrypted file should exist");

    // Inspect should show valid signature
    cmd()
        .arg("inspect")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature Verification"))
        .stdout(predicate::str::contains("OK"));
}

#[test]
fn test_verify_kv_enc_valid_signature() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Set a KV value to create an encrypted KV file
    cmd()
        .arg("set")
        .arg("VERIFY_KEY")
        .arg("verify_value")
        .arg("--member-handle")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    let encrypted_kv = workspace_dir.path().join("secrets").join("default.kvenc");
    assert!(encrypted_kv.exists(), "Encrypted KV file should exist");

    // Inspect should show valid signature
    cmd()
        .arg("inspect")
        .arg(encrypted_kv.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature Verification"))
        .stdout(predicate::str::contains("OK"));
}

#[test]
fn test_verify_file_enc_tampered_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Create and encrypt a file
    let input_file = home_dir.path().join("tamper_test.bin");
    fs::write(&input_file, b"content to be tampered").unwrap();

    let encrypted_file = home_dir.path().join("tamper_test.bin.encrypted");

    cmd()
        .arg("encrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--member-handle")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Read the encrypted file, parse JSON, tamper with the signature
    let content = fs::read_to_string(&encrypted_file).unwrap();
    let mut doc: serde_json::Value = serde_json::from_str(&content).unwrap();

    // Tamper with the signature field (use a valid base64url-encoded 64-byte value
    // so it passes schema validation but fails signature verification)
    if let Some(sig_obj) = doc.get_mut("signature") {
        if let Some(sig_field) = sig_obj.get_mut("sig") {
            // 86-char base64url string representing 64 zero bytes
            *sig_field = serde_json::Value::String(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    .to_string(),
            );
        }
    }

    let tampered_content = serde_json::to_string_pretty(&doc).unwrap();
    fs::write(&encrypted_file, tampered_content).unwrap();

    // Inspect should succeed (exit code 0) even with tampered signature,
    // showing metadata with verification Status: FAILED (graceful degradation per PRD)
    cmd()
        .arg("inspect")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("FAILED"));
}

#[test]
fn test_verify_nonexistent_file_fails() {
    let temp_dir = TempDir::new().unwrap();
    let nonexistent = temp_dir.path().join("nonexistent.encrypted");

    cmd()
        .arg("inspect")
        .arg(nonexistent.to_str().unwrap())
        .assert()
        .failure();
}
