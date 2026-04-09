// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn test_rewrap_file_enc_roundtrip() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let original_content = b"\x00\x01\x02binary-test-data\xff\xfe";
    let input_file = home_dir.path().join("secret.bin");
    fs::write(&input_file, original_content).unwrap();

    let encrypted_file = workspace_dir.path().join("secrets").join("secret.bin.json");
    let decrypted_file = home_dir.path().join("decrypted.bin");

    cmd()
        .arg("encrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    assert!(encrypted_file.exists(), "Encrypted file should exist");

    cmd()
        .arg("rewrap")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("decrypt")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--out")
        .arg(decrypted_file.to_str().unwrap())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    assert!(decrypted_file.exists(), "Decrypted file should exist");
    let decrypted_content = fs::read(&decrypted_file).unwrap();
    assert_eq!(
        decrypted_content, original_content,
        "Decrypted content should match original after rewrap"
    );
}

#[test]
fn test_rewrap_kv_enc_roundtrip() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    cmd()
        .arg("set")
        .arg("MY_SECRET")
        .arg("supersecretvalue")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("rewrap")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("get")
        .arg("MY_SECRET")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("supersecretvalue"));
}
