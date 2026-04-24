// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Format tests for encrypt command
//!
//! encrypt コマンドは常に file-enc を出力する（format 自動判別は廃止）。

use crate::cli::common::{default_common_options, set_ssh_key_from_temp_dir, ALICE_MEMBER_ID};
use crate::test_utils::setup_test_workspace;
use secretenv::cli::encrypt;
use secretenv::model::identifiers::format;
use std::fs;

#[test]
fn test_encrypt_always_produces_file_enc_for_binary() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);

    let input_path = workspace_dir.join("data.bin");
    fs::write(&input_path, [0x00, 0x01, 0x02, 0x03]).unwrap();
    let output_path = workspace_dir.join("data.bin.encrypted");

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let args = encrypt::EncryptArgs {
        common: common_opts,
        member_handle: Some(ALICE_MEMBER_ID.to_string()),
        out: Some(output_path.clone()),
        stdout: false,
        stdin: false,
        input: Some(input_path),
    };
    encrypt::run(args).unwrap();

    let content = fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["protected"]["format"], format::FILE_ENC_V3);
}

#[test]
fn test_encrypt_always_produces_file_enc_for_dotenv() {
    // dotenv content も file-enc として暗号化される（kv-enc は set コマンドのみ）
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);

    let input_path = workspace_dir.join("app.env");
    fs::write(
        &input_path,
        "DATABASE_URL=postgres://localhost\nAPI_KEY=secret\n",
    )
    .unwrap();
    let output_path = workspace_dir.join("app.env.encrypted");

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let args = encrypt::EncryptArgs {
        common: common_opts,
        member_handle: Some(ALICE_MEMBER_ID.to_string()),
        out: Some(output_path.clone()),
        stdout: false,
        stdin: false,
        input: Some(input_path),
    };
    encrypt::run(args).unwrap();

    let content = fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(
        parsed["protected"]["format"],
        format::FILE_ENC_V3,
        "dotenv content should also be encrypted as file-enc"
    );
}
