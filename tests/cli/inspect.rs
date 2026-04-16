// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for inspect command
//!
//! Tests the inspect command with file-enc and kv-enc formats,
//! invalid inputs, and signature verification display.

use crate::cli::common::{
    cmd, default_common_options, set_ssh_key_from_temp_dir, setup_workspace, ALICE_MEMBER_ID,
    BOB_MEMBER_ID, TEST_MEMBER_ID,
};
use crate::test_utils::{
    build_expiring_soon_timestamp, setup_member_key_context, setup_test_workspace,
    setup_trust_store_for_workspace, update_active_private_key_expires_at,
};
use console::strip_ansi_codes;
use predicates::prelude::*;
use secretenv::cli::rewrap::{self, RewrapArgs};
use secretenv::cli::set;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_inspect_file_enc_shows_metadata() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Create a test file and encrypt it
    let input_file = home_dir.path().join("secret.txt");
    fs::write(&input_file, b"hello secret world").unwrap();

    let encrypted_file = home_dir.path().join("secret.txt.encrypted");

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

    // Inspect the encrypted file
    cmd()
        .arg("inspect")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("File-Enc v3 Metadata"))
        .stdout(predicate::str::contains("Format:"))
        .stdout(predicate::str::contains("SID:"))
        .stdout(predicate::str::contains("Recipients"))
        .stdout(predicate::str::contains("Signature"));

    // Even when signature verification information is unavailable/failed,
    // embedded attestation metadata should still be inspectable.
    cmd()
        .arg("inspect")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Attestation:"));
}

#[test]
fn test_inspect_kv_enc_shows_metadata() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Set a KV value to create an encrypted KV file
    cmd()
        .arg("set")
        .arg("DB_URL")
        .arg("pg://host")
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    let encrypted_kv = workspace_dir.path().join("secrets").join("default.kvenc");
    assert!(encrypted_kv.exists(), "Encrypted KV file should exist");

    // Inspect the KV encrypted file
    cmd()
        .arg("inspect")
        .arg(encrypted_kv.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("KV-Enc Metadata"))
        .stdout(predicate::str::contains("Header"))
        .stdout(predicate::str::contains("Wrap Data"))
        .stdout(predicate::str::contains("Entries"))
        .stdout(predicate::str::contains("Signature"));

    cmd()
        .arg("inspect")
        .arg(encrypted_kv.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Attestation:"));
}

#[test]
fn test_inspect_invalid_format_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Create a plain text file (not encrypted)
    let plain_file = home_dir.path().join("plain.txt");
    fs::write(&plain_file, "This is just plain text, not encrypted.").unwrap();

    cmd()
        .arg("inspect")
        .arg(plain_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

#[test]
fn test_inspect_nonexistent_file_fails() {
    let temp_dir = TempDir::new().unwrap();
    let nonexistent = temp_dir.path().join("does_not_exist.encrypted");

    cmd()
        .arg("inspect")
        .arg(nonexistent.to_str().unwrap())
        .assert()
        .failure();
}

#[test]
fn test_inspect_shows_signature_verification() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Create and encrypt a file
    let input_file = home_dir.path().join("secret_for_sig.txt");
    fs::write(&input_file, b"signature test data").unwrap();

    let encrypted_file = home_dir.path().join("secret_for_sig.txt.encrypted");

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

    // Inspect should show signature verification section
    cmd()
        .arg("inspect")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature Verification"))
        .stdout(predicate::str::contains("Status:"));
}

#[test]
fn test_inspect_kv_shows_entry_count() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Set a KV value
    cmd()
        .arg("set")
        .arg("API_KEY")
        .arg("secret123")
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    let encrypted_kv = workspace_dir.path().join("secrets").join("default.kvenc");
    assert!(encrypted_kv.exists(), "Encrypted KV file should exist");

    // Inspect should show total entry count
    cmd()
        .arg("inspect")
        .arg(encrypted_kv.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Total Entries: 1"));
}

#[test]
fn test_inspect_succeeds_without_workspace_or_private_key() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let input_file = home_dir.path().join("no_private_key.txt");
    fs::write(&input_file, b"inspect without private key").unwrap();

    let encrypted_file = home_dir.path().join("no_private_key.txt.encrypted");
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

    cmd()
        .arg("inspect")
        .arg(encrypted_file.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature Verification"))
        .stdout(predicate::str::contains("Status:"));
}

#[test]
fn test_inspect_ignores_trust_store_and_strict_key_checking() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let input_file = home_dir.path().join("ignore_trust.txt");
    fs::write(&input_file, b"inspect ignores trust store").unwrap();

    let encrypted_file = home_dir.path().join("ignore_trust.txt.encrypted");
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

    let trust_dir = home_dir.path().join("trust");
    fs::create_dir_all(&trust_dir).unwrap();
    fs::write(
        trust_dir.join(format!("{}.json", TEST_MEMBER_ID)),
        "{ this is not valid trust store json",
    )
    .unwrap();

    cmd()
        .arg("inspect")
        .arg(encrypted_file.to_str().unwrap())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_STRICT_KEY_CHECKING", "no")
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature Verification"))
        .stdout(predicate::str::contains("Status:"));
}

#[test]
fn test_inspect_colors_public_key_expiry_warning_when_forced() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let ssh_pub = ssh_priv.with_extension("pub");
    fs::create_dir_all(home_dir.path().join(".ssh")).unwrap();
    fs::copy(&ssh_priv, home_dir.path().join(".ssh").join("test_ed25519")).unwrap();
    fs::copy(
        &ssh_pub,
        home_dir.path().join(".ssh").join("test_ed25519.pub"),
    )
    .unwrap();
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(home_dir.path(), TEST_MEMBER_ID, &expires_at);

    let input_file = home_dir.path().join("inspect_warning.txt");
    fs::write(&input_file, b"inspect warning test").unwrap();

    let encrypted_file = home_dir.path().join("inspect_warning.txt.encrypted");
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

    let assert = cmd()
        .arg("inspect")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .env("CLICOLOR_FORCE", "1")
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(
        stdout.contains("\u{1b}[33m  Warning:     \u{26a0} PublicKey for '"),
        "expected ANSI-colored inspect warning in stdout, got: {}",
        stdout
    );
    assert!(
        strip_ansi_codes(&stdout).contains("Warning:     \u{26a0} PublicKey for '"),
        "expected inspect warning text after stripping ANSI, got: {}",
        stdout
    );
}

#[test]
fn test_inspect_colors_disclosed_rotation_warning_when_forced() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let set_args = set::SetArgs {
        common: common_opts.clone(),
        member_id: Some(ALICE_MEMBER_ID.to_string()),
        name: Some("disclosed".to_string()),
        key: "API_KEY".to_string(),
        value: Some("secret123".to_string()),
        stdin: false,
    };
    set::run(set_args).unwrap();

    fs::remove_file(
        workspace_dir
            .join("members/active")
            .join(format!("{}.json", BOB_MEMBER_ID)),
    )
    .unwrap();

    let rewrap_args = RewrapArgs {
        common: common_opts,
        clear_disclosure_history: false,
        member_id: Some(ALICE_MEMBER_ID.to_string()),
        rotate_key: false,
        targets: Vec::new(),
    };
    rewrap::run(rewrap_args).unwrap();

    let encrypted_kv = workspace_dir.join("secrets").join("disclosed.kvenc");
    let ssh_identity = temp_dir.path().join(".ssh").join("test_ed25519");
    let assert = cmd()
        .arg("inspect")
        .arg(&encrypted_kv)
        .arg("--workspace")
        .arg(&workspace_dir)
        .env("SECRETENV_HOME", temp_dir.path())
        .env("SECRETENV_SSH_IDENTITY", &ssh_identity)
        .env("CLICOLOR_FORCE", "1")
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(
        stdout.contains(
            "\u{1b}[33m      \u{26a0} DISCLOSED \u{2014} Secret may need rotation\u{1b}[0m"
        ),
        "expected ANSI-colored disclosed warning in stdout, got: {}",
        stdout
    );
    assert!(
        strip_ansi_codes(&stdout).contains("\u{26a0} DISCLOSED \u{2014} Secret may need rotation"),
        "expected disclosed warning text after stripping ANSI, got: {}",
        stdout
    );
}
