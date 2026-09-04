// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Recipient-related encryption tests
//!
//! Covers how the encrypt command behaves for a workspace with several active
//! members. The recipient set an artifact ends up with is fixed by the unit
//! tests instead, which can read the document without parsing CLI output.

use crate::cli::common::{
    cmd, encrypt_file_with_member_set_review, ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE,
    CAROL_MEMBER_HANDLE,
};
use crate::test_utils::setup_trust_store_for_workspace;
use kapsaro_test_support::crypto_context::setup_member_key_context;
use kapsaro_test_support::fixture::setup_test_workspace;
use std::fs;

#[test]
fn test_encrypt_with_all_active_members_approved() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE, CAROL_MEMBER_HANDLE]);

    // Set up trust store with all active members approved
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    let input_path = workspace_dir.join("secret.bin");
    fs::write(&input_path, b"secret data").unwrap();
    let output_path = workspace_dir.join("secret.encrypted");

    let ssh_identity = temp_dir.path().join(".ssh").join("test_ed25519");
    encrypt_file_with_member_set_review(
        &workspace_dir,
        temp_dir.path(),
        &ssh_identity,
        &input_path,
        &output_path,
        ALICE_MEMBER_HANDLE,
    );

    assert!(output_path.exists());
}

#[test]
fn test_encrypt_workspace_required() {
    use crate::test_utils::with_temp_cwd;
    use kapsaro_test_support::fixture::setup_test_keystore;
    let temp_dir = setup_test_keystore(ALICE_MEMBER_HANDLE);
    let test_dir = temp_dir.path();
    with_temp_cwd(test_dir, || {
        let input_path = test_dir.join("test.bin");
        fs::write(&input_path, b"data").unwrap();

        cmd()
            .arg("encrypt")
            .arg(&input_path)
            .arg("--out")
            .arg(test_dir.join("out.encrypted"))
            .arg("--member-handle")
            .arg(ALICE_MEMBER_HANDLE)
            .env("KAPSARO_HOME", temp_dir.path())
            .env(
                "KAPSARO_SSH_IDENTITY",
                temp_dir.path().join(".ssh").join("test_ed25519"),
            )
            .assert()
            .failure();
    })
}
