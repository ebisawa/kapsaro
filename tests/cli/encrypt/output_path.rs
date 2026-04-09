// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Output path-related encryption tests

use crate::cli::common::{
    cmd, default_common_options, set_ssh_key_from_temp_dir, setup_workspace, ALICE_MEMBER_ID,
    TEST_MEMBER_ID,
};
use crate::test_utils::{setup_test_workspace, with_temp_cwd};
use predicates::prelude::*;
use secretenv::cli::encrypt;
use secretenv::model::identifiers::format;
use std::fs;

#[test]
fn test_encrypt_default_output_is_encrypted_in_cwd() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);

    let input_path = workspace_dir.join("data.bin");
    fs::write(&input_path, b"some data").unwrap();

    with_temp_cwd(&workspace_dir, || {
        let mut common_opts = default_common_options();
        common_opts.home = Some(temp_dir.path().to_path_buf());
        common_opts.workspace = Some(workspace_dir.clone());
        set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

        let args = encrypt::EncryptArgs {
            common: common_opts,
            member_id: Some(ALICE_MEMBER_ID.to_string()),
            input: input_path.clone(),
            out: None,
        };
        encrypt::run(args).unwrap();

        // Default output: <input_filename>.encrypted in current dir (= workspace_dir)
        let expected = workspace_dir.join("data.bin.encrypted");
        assert!(expected.exists(), "Should create data.bin.encrypted in cwd");

        let content = fs::read_to_string(&expected).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["protected"]["format"], format::FILE_ENC_V3);
    })
}

#[test]
fn test_encrypt_explicit_out_option() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);

    let input_path = workspace_dir.join("test.bin");
    fs::write(&input_path, b"data").unwrap();
    let explicit_output = workspace_dir.join("custom_output.encrypted");

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let args = encrypt::EncryptArgs {
        common: common_opts,
        member_id: Some(ALICE_MEMBER_ID.to_string()),
        input: input_path,
        out: Some(explicit_output.clone()),
    };
    encrypt::run(args).unwrap();

    assert!(
        explicit_output.exists(),
        "File should be at explicit --out path"
    );
}

#[test]
fn test_encrypt_explicit_out_option_reports_output_path() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let input_file = home_dir.path().join("data.txt");
    let output_file = home_dir.path().join("custom_output.encrypted");
    fs::write(&input_file, b"secret").unwrap();

    cmd()
        .arg("encrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(output_file.to_str().unwrap())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains("Encrypted to:"))
        .stderr(predicate::str::contains("custom_output.encrypted"));
}
