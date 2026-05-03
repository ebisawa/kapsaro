// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Output path-related encryption tests

use crate::cli::common::{
    cmd, default_common_options, set_ssh_key_from_temp_dir, setup_workspace, ALICE_MEMBER_HANDLE,
    TEST_MEMBER_HANDLE,
};
use crate::test_utils::{setup_test_workspace, with_temp_cwd};
use predicates::prelude::*;
use secretenv::cli::encrypt;
use secretenv::model::identifiers::format;
use std::fs;

#[test]
fn test_encrypt_default_output_is_encrypted_in_cwd() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);

    let input_path = workspace_dir.join("data.bin");
    fs::write(&input_path, b"some data").unwrap();

    with_temp_cwd(&workspace_dir, || {
        let mut common_opts = default_common_options();
        common_opts.home = Some(temp_dir.path().to_path_buf());
        common_opts.workspace = Some(workspace_dir.clone());
        set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

        let args = encrypt::EncryptArgs {
            common: common_opts,
            member_handle: Some(ALICE_MEMBER_HANDLE.to_string()),
            out: None,
            stdout: false,
            stdin: false,
            input: Some(input_path.clone()),
        };
        encrypt::run(args).unwrap();

        // Default output: <input_filename>.encrypted in current dir (= workspace_dir)
        let expected = workspace_dir.join("data.bin.encrypted");
        assert!(expected.exists(), "Should create data.bin.encrypted in cwd");

        let content = fs::read_to_string(&expected).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["protected"]["format"], format::FILE_ENC_V4);
    })
}

#[test]
fn test_encrypt_explicit_out_option() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);

    let input_path = workspace_dir.join("test.bin");
    fs::write(&input_path, b"data").unwrap();
    let explicit_output = workspace_dir.join("custom_output.encrypted");

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let args = encrypt::EncryptArgs {
        common: common_opts,
        member_handle: Some(ALICE_MEMBER_HANDLE.to_string()),
        out: Some(explicit_output.clone()),
        stdout: false,
        stdin: false,
        input: Some(input_path),
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
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains("Encrypted to:"))
        .stderr(predicate::str::contains("custom_output.encrypted"));
}

#[test]
fn test_encrypt_stdin_with_out_option_writes_encrypted_file() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let output_file = home_dir.path().join("stdin_output.encrypted");

    cmd()
        .arg("encrypt")
        .arg("--stdin")
        .arg("--out")
        .arg(&output_file)
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin("secret from stdin")
        .assert()
        .success()
        .stderr(predicate::str::contains("stdin_output.encrypted"));

    let content = fs::read_to_string(&output_file).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["protected"]["format"], format::FILE_ENC_V4);
}

#[test]
fn test_encrypt_stdin_with_stdout_writes_json_to_stdout() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let assert = cmd()
        .arg("encrypt")
        .arg("--stdin")
        .arg("--stdout")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin("secret from stdin")
        .assert()
        .success()
        .stderr(predicate::str::contains("Encrypted to:").not());

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["protected"]["format"], format::FILE_ENC_V4);
}

#[test]
fn test_encrypt_file_with_stdout_writes_json_to_stdout() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let input_file = home_dir.path().join("data.txt");
    fs::write(&input_file, b"secret").unwrap();

    let assert = cmd()
        .arg("encrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--stdout")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains("Encrypted to:").not());

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["protected"]["format"], format::FILE_ENC_V4);
}

#[test]
fn test_encrypt_stdin_requires_out_or_stdout() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    cmd()
        .arg("encrypt")
        .arg("--stdin")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin("secret from stdin")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--stdin requires either --out or --stdout",
        ));
}

#[test]
fn test_encrypt_rejects_stdout_and_out_together() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let input_file = home_dir.path().join("data.txt");
    let output_file = home_dir.path().join("custom_output.encrypted");
    fs::write(&input_file, b"secret").unwrap();

    cmd()
        .arg("encrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--stdout")
        .arg("--out")
        .arg(&output_file)
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("--stdout").and(predicate::str::contains("--out")));
}

#[test]
fn test_encrypt_stdin_stdout_roundtrip_preserves_binary_bytes() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let encrypted_file = home_dir.path().join("stdin_binary.encrypted");
    let decrypted_file = home_dir.path().join("stdin_binary.out");
    let plaintext = vec![0x00, 0x01, 0x02, b'a', b'\n', 0xff];

    let encrypt = cmd()
        .arg("encrypt")
        .arg("--stdin")
        .arg("--stdout")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin(plaintext.clone())
        .assert()
        .success();

    fs::write(&encrypted_file, encrypt.get_output().stdout.clone()).unwrap();

    cmd()
        .arg("decrypt")
        .arg(&encrypted_file)
        .arg("--out")
        .arg(&decrypted_file)
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    assert_eq!(fs::read(&decrypted_file).unwrap(), plaintext);
}
