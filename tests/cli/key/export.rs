// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `key export` command

use crate::cli::common::{cmd, create_temp_ssh_keypair, TEST_MEMBER_ID};
use crate::cli::key::find_kid_in_member_dir;
use predicates::prelude::*;
use secretenv::model::identifiers::format;
use secretenv::model::private_key::PrivateKey;
use secretenv::model::public_key::PublicKey;
use secretenv::support::codec::base64_public::decode_base64url_nopad;
use secretenv::support::kid::build_kid_display;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_key_export_explicit_kid() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = create_temp_ssh_keypair();

    let member_id = TEST_MEMBER_ID;

    // Generate a key
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_id)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Get the kid
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_id);
    let kid = find_kid_in_member_dir(&member_dir);

    // Export to a temp file
    let export_file = temp_dir.path().join("exported.json");

    cmd()
        .arg("key")
        .arg("export")
        .arg(&kid)
        .arg("--member-handle")
        .arg(member_id)
        .arg("--out")
        .arg(export_file.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Verify exported file exists and is valid JSON
    assert!(export_file.exists(), "Exported file should exist");

    let exported_json = fs::read_to_string(&export_file).expect("Should read exported file");
    let exported: PublicKey =
        serde_json::from_str(&exported_json).expect("Exported file should be valid PublicKey JSON");

    // Verify fields
    assert_eq!(exported.protected.kid, kid, "Exported kid should match");
    assert_eq!(
        exported.protected.member_id, member_id,
        "Exported member_id should match"
    );
    assert_eq!(
        exported.protected.format,
        format::PUBLIC_KEY_V4,
        "Exported format should be v3"
    );

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_export_active() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = create_temp_ssh_keypair();

    let member_id = TEST_MEMBER_ID;

    // Generate a key
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_id)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Export active key to a temp file
    let export_file = temp_dir.path().join("exported.json");

    cmd()
        .arg("key")
        .arg("export")
        .arg("--member-handle")
        .arg(member_id)
        .arg("--out")
        .arg(export_file.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Verify exported file exists and is valid
    assert!(export_file.exists(), "Exported file should exist");

    let exported_json = fs::read_to_string(&export_file).expect("Should read exported file");
    let exported: PublicKey =
        serde_json::from_str(&exported_json).expect("Exported file should be valid PublicKey JSON");

    assert_eq!(
        exported.protected.format,
        format::PUBLIC_KEY_V4,
        "Exported format should be v3"
    );

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_export_accepts_display_kid() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = create_temp_ssh_keypair();
    let member_id = TEST_MEMBER_ID;

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_id)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_id);
    let kid = find_kid_in_member_dir(&member_dir);
    let export_file = temp_dir.path().join("display-exported.json");

    cmd()
        .arg("key")
        .arg("export")
        .arg(build_kid_display(&kid).unwrap())
        .arg("--member-handle")
        .arg(member_id)
        .arg("--out")
        .arg(export_file.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    let exported_json = fs::read_to_string(&export_file).unwrap();
    let exported: PublicKey = serde_json::from_str(&exported_json).unwrap();
    assert_eq!(exported.protected.kid, kid);

    drop(ssh_temp);
}

#[test]
fn test_key_export_private_writes_password_protected_key_file() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = create_temp_ssh_keypair();
    let member_id = TEST_MEMBER_ID;

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_id)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    let export_file = temp_dir.path().join("portable-private-key.txt");

    cmd()
        .arg("key")
        .arg("export")
        .arg("--private")
        .arg("--member-handle")
        .arg(member_id)
        .arg("--out")
        .arg(export_file.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin("strong-password-42\nstrong-password-42\n")
        .assert()
        .success();

    let exported = fs::read_to_string(&export_file).expect("Should read exported private key");
    let json = decode_base64url_nopad(exported.trim(), "exported private key")
        .expect("Should decode as base64url");
    let private_key: PrivateKey =
        serde_json::from_slice(&json).expect("Should deserialize as PrivateKey");

    assert_eq!(private_key.protected.member_id, member_id);
    assert_eq!(private_key.protected.format, format::PRIVATE_KEY_V5);

    drop(ssh_temp);
}

#[test]
fn test_key_export_private_writes_base64url_to_stdout_with_stdout_flag() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = create_temp_ssh_keypair();
    let member_id = TEST_MEMBER_ID;

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_id)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    let output = cmd()
        .arg("key")
        .arg("export")
        .arg("--private")
        .arg("--stdout")
        .arg("--member-handle")
        .arg(member_id)
        .env("SECRETENV_HOME", temp_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin("strong-password-42\nstrong-password-42\n")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).expect("stdout should be UTF-8");
    let exported = stdout.trim();
    assert!(!exported.is_empty(), "stdout should contain exported key");

    let json = decode_base64url_nopad(exported, "stdout private key")
        .expect("Should decode stdout as base64url");
    let private_key: PrivateKey =
        serde_json::from_slice(&json).expect("Should deserialize stdout as PrivateKey");

    assert_eq!(private_key.protected.member_id, member_id);
    assert_eq!(private_key.protected.format, format::PRIVATE_KEY_V5);

    drop(ssh_temp);
}

#[test]
fn test_key_export_private_requires_member_id_before_password_input() {
    let temp_dir = TempDir::new().unwrap();

    cmd()
        .arg("key")
        .arg("export")
        .arg("--private")
        .arg("--stdout")
        .env("SECRETENV_HOME", temp_dir.path())
        .write_stdin("strong-password-42\n")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("member handle not configured")
                .and(predicate::str::contains("Passwords do not match").not()),
        );
}

#[test]
fn test_key_export_private_requires_explicit_output_destination() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = create_temp_ssh_keypair();
    let member_id = TEST_MEMBER_ID;

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_id)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    cmd()
        .arg("key")
        .arg("export")
        .arg("--private")
        .arg("--member-handle")
        .arg(member_id)
        .env("SECRETENV_HOME", temp_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stdout(predicates::prelude::predicate::str::is_empty())
        .stderr(predicates::prelude::predicate::str::contains(
            "requires either --out or --stdout",
        ));

    drop(ssh_temp);
}

#[test]
fn test_key_export_private_rejects_stdout_and_out_together() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = create_temp_ssh_keypair();
    let member_id = TEST_MEMBER_ID;

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_id)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    let export_file = temp_dir.path().join("portable-private-key.txt");

    cmd()
        .arg("key")
        .arg("export")
        .arg("--private")
        .arg("--stdout")
        .arg("--member-handle")
        .arg(member_id)
        .arg("--out")
        .arg(export_file.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicates::prelude::predicate::str::contains(
            "cannot be used with",
        ));

    drop(ssh_temp);
}
