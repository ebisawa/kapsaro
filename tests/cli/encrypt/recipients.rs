// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Recipient-related encryption tests
//!
//! encrypt は常に workspace の全 active メンバーを recipients とする。

use crate::cli::common::{
    cmd, encrypt_file_with_member_set_review, ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE,
    CAROL_MEMBER_HANDLE,
};
use crate::test_utils::{
    setup_member_key_context, setup_test_workspace, setup_trust_store_for_workspace,
};
use std::fs;

#[test]
fn test_encrypt_recipients_are_all_active_members() {
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

    let content = fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    let wrap = parsed["protected"]["wrap"].as_array().unwrap();
    assert_eq!(wrap.len(), 3, "All 3 active members should be recipients");

    let recipient_handles: Vec<&str> = wrap.iter().map(|w| w["rh"].as_str().unwrap()).collect();
    assert!(recipient_handles.contains(&ALICE_MEMBER_HANDLE));
    assert!(recipient_handles.contains(&BOB_MEMBER_HANDLE));
    assert!(recipient_handles.contains(&CAROL_MEMBER_HANDLE));
}

#[test]
fn test_encrypt_workspace_required() {
    use crate::test_utils::{setup_test_keystore, with_temp_cwd};
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
