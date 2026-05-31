// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Output path-related encryption tests

use crate::cli::common::{
    cmd, encrypt_file_with_member_set_review, encrypt_stdin_with_member_set_review,
    setup_workspace, ALICE_MEMBER_HANDLE, TEST_MEMBER_HANDLE,
};
use crate::test_utils::{setup_test_workspace, with_temp_cwd};
use kapsaro_core::cli_api::test_support::domain::wire::format;
use predicates::prelude::*;
use std::fs;

fn parse_json_from_transcript(transcript: &str) -> serde_json::Value {
    let start = transcript
        .find('{')
        .expect("transcript should contain JSON");
    serde_json::from_str(&transcript[start..]).expect("stdout JSON should parse")
}

#[test]
fn test_encrypt_default_output_is_encrypted_in_cwd() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);

    let input_path = workspace_dir.join("data.bin");
    fs::write(&input_path, b"some data").unwrap();

    with_temp_cwd(&workspace_dir, || {
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

        // Default output: <input_filename>.encrypted in current dir (= workspace_dir)
        let expected = output_path;
        assert!(expected.exists(), "Should create data.bin.encrypted in cwd");

        let content = fs::read_to_string(&expected).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["protected"]["format"], format::FILE_ENC_V1);
    })
}

#[test]
fn test_encrypt_explicit_out_option_reports_output_path() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let input_file = home_dir.path().join("data.txt");
    let output_file = home_dir.path().join("custom_output.encrypted");
    fs::write(&input_file, b"secret").unwrap();

    let output = encrypt_file_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        &input_file,
        &output_file,
        TEST_MEMBER_HANDLE,
    );
    assert!(output.contains("Encrypted to:"), "{output}");
    assert!(output.contains("custom_output.encrypted"), "{output}");
}

#[test]
fn test_encrypt_stdin_with_out_option_writes_encrypted_file() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let output_file = home_dir.path().join("stdin_output.encrypted");

    let output = encrypt_stdin_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        b"secret from stdin",
        Some(&output_file),
        false,
        TEST_MEMBER_HANDLE,
    );
    assert!(output.contains("stdin_output.encrypted"), "{output}");

    let content = fs::read_to_string(&output_file).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["protected"]["format"], format::FILE_ENC_V1);
}

#[test]
fn test_encrypt_stdin_with_stdout_writes_json_to_stdout() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let output = encrypt_stdin_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        b"secret from stdin",
        None,
        true,
        TEST_MEMBER_HANDLE,
    );
    assert!(!output.contains("Encrypted to:"), "{output}");
    let parsed = parse_json_from_transcript(&output);
    assert_eq!(parsed["protected"]["format"], format::FILE_ENC_V1);
}

#[test]
fn test_encrypt_file_with_stdout_writes_json_to_stdout() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let input_file = home_dir.path().join("data.txt");
    fs::write(&input_file, b"secret").unwrap();

    let mut command = crate::cli::common::kapsaro_std_cmd();
    command
        .arg("encrypt")
        .arg(&input_file)
        .arg("--stdout")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", &ssh_priv);
    let output = crate::cli::common::assert_member_set_review_success(&mut command);
    assert!(!output.contains("Encrypted to:"), "{output}");
    let parsed = parse_json_from_transcript(&output);
    assert_eq!(parsed["protected"]["format"], format::FILE_ENC_V1);
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
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
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
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("--stdout").and(predicate::str::contains("--out")));
}

#[test]
fn test_encrypt_stdin_stdout_roundtrip_preserves_binary_bytes() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let plaintext = vec![0x00, 0x01, 0x02, b'a', b'\n', 0xff];

    let encrypted_output = cmd()
        .arg("encrypt")
        .arg("--stdin")
        .arg("--stdout")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin(plaintext.clone())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let decrypted_output = cmd()
        .arg("decrypt")
        .arg("--stdin")
        .arg("--stdout")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin(encrypted_output)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(decrypted_output, plaintext);
}

#[test]
fn test_encrypt_rejects_control_character_input_filename_for_default_output() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let input_file = home_dir.path().join("bad\nname.txt");
    fs::write(&input_file, b"secret").unwrap();

    cmd()
        .arg("encrypt")
        .arg(&input_file)
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("E_NAME_INVALID"));
}

#[test]
fn test_encrypt_quiet_suppresses_output_path_notice() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let input_file = home_dir.path().join("quiet.txt");
    let output_file = home_dir.path().join("quiet.txt.encrypted");
    fs::write(&input_file, b"quiet secret").unwrap();

    let mut command = crate::cli::common::kapsaro_std_cmd();
    command
        .arg("encrypt")
        .arg(&input_file)
        .arg("--out")
        .arg(&output_file)
        .arg("--quiet")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", &ssh_priv);

    let output = crate::cli::common::assert_member_set_review_success(&mut command);

    assert!(output_file.exists());
    assert!(!output.contains("Encrypted to:"), "{output}");
}
