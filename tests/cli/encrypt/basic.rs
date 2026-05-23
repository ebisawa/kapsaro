// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Basic encryption tests

use crate::cli::common::{cmd, encrypt_file_with_member_set_review, ALICE_MEMBER_HANDLE};
use crate::test_utils::{setup_test_keystore, setup_test_workspace};
use secretenv_core::cli_api::test_support::domain::wire::format;
use std::fs;

#[test]
fn test_encrypt_file_with_workspace() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);

    let input_path = workspace_dir.join("secret.bin");
    fs::write(&input_path, b"secret binary content").unwrap();
    let output_path = workspace_dir.join("secret.bin.encrypted");

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
    let content = fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["protected"]["format"], format::FILE_ENC_V6);
}

#[test]
fn test_encrypt_no_active_members_error() {
    use tempfile::TempDir;
    let workspace_tmp = TempDir::new().unwrap();
    let workspace_dir = workspace_tmp.path().join("workspace");
    fs::create_dir_all(workspace_dir.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir.join("members/incoming")).unwrap();
    fs::create_dir_all(workspace_dir.join("secrets")).unwrap();

    let input_path = workspace_dir.join("test.bin");
    fs::write(&input_path, b"data").unwrap();

    let keystore_tmp = setup_test_keystore(ALICE_MEMBER_HANDLE);
    let output = cmd()
        .arg("encrypt")
        .arg(&input_path)
        .arg("--out")
        .arg(workspace_dir.join("output.encrypted"))
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .env("SECRETENV_HOME", keystore_tmp.path())
        .env(
            "SECRETENV_SSH_IDENTITY",
            keystore_tmp.path().join(".ssh").join("test_ed25519"),
        )
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "Should fail with no active members"
    );
    let err_msg = String::from_utf8_lossy(&output.stderr);
    assert!(
        err_msg.contains("No active members")
            || err_msg.contains("No members")
            || err_msg.contains("empty"),
        "Error should mention no active members: {}",
        err_msg
    );
}
