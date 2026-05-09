// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Format tests for encrypt command
//!
//! encrypt コマンドは常に file-enc を出力する（format 自動判別は廃止）。

use crate::cli::common::{encrypt_file_with_member_set_review, ALICE_MEMBER_HANDLE};
use crate::test_utils::setup_test_workspace;
use secretenv::model::wire::format;
use std::fs;

#[test]
fn test_encrypt_always_produces_file_enc_for_binary() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);

    let input_path = workspace_dir.join("data.bin");
    fs::write(&input_path, [0x00, 0x01, 0x02, 0x03]).unwrap();
    let output_path = workspace_dir.join("data.bin.encrypted");

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
    assert_eq!(parsed["protected"]["format"], format::FILE_ENC_V5);
}

#[test]
fn test_encrypt_always_produces_file_enc_for_dotenv() {
    // dotenv content も file-enc として暗号化される（kv-enc は set コマンドのみ）
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);

    let input_path = workspace_dir.join("app.env");
    fs::write(
        &input_path,
        "DATABASE_URL=postgres://localhost\nAPI_KEY=secret\n",
    )
    .unwrap();
    let output_path = workspace_dir.join("app.env.encrypted");

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
    assert_eq!(
        parsed["protected"]["format"],
        format::FILE_ENC_V5,
        "dotenv content should also be encrypted as file-enc"
    );
}
