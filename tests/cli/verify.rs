// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests inspect's signature failure display for tampered file artifacts.
//! Normal signature status is covered alongside the inspect metadata fields.

use crate::cli::common::{
    cmd, encrypt_file_with_member_set_review, setup_workspace, TEST_MEMBER_HANDLE,
};
use predicates::prelude::*;
use std::fs;

#[test]
fn test_verify_file_enc_tampered_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Create and encrypt a file
    let input_file = home_dir.path().join("tamper_test.bin");
    fs::write(&input_file, b"content to be tampered").unwrap();

    let encrypted_file = home_dir.path().join("tamper_test.bin.encrypted");

    encrypt_file_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        &input_file,
        &encrypted_file,
        TEST_MEMBER_HANDLE,
    );

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

    // Inspect reports metadata for an artifact it cannot verify rather than
    // refusing to run, so a failed signature still exits 0 with Status: FAILED.
    cmd()
        .arg("inspect")
        .arg(encrypted_file.to_str().unwrap())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("FAILED"));
}
