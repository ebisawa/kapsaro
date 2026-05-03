// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CLI integration tests for env key mode (CI mode)
//!
//! Tests that env key mode is restricted to read-only operations:
//! `run`, `decrypt`, and `get`.

use crate::cli::common::{cmd, setup_workspace, TEST_MEMBER_HANDLE};
use crate::test_utils::ed25519_backend::Ed25519DirectBackend;
use predicates::prelude::*;
use secretenv::feature::key::portable_export::export_private_key_portable;
use secretenv::feature::key::protection::encryption::decrypt_private_key;
use secretenv::io::keystore::active::load_active_kid;
use secretenv::io::keystore::storage::load_private_key;
use secretenv::support::secret::SecretString;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "cli-integration-test-password-42";
const ENV_MODE_UNSUPPORTED_MESSAGE: &str =
    "env mode only supports these commands: run, decrypt, get, list";

// ============================================================================
// Setup Helper
// ============================================================================

/// Setup a workspace with an exported portable private key for env key mode.
///
/// Returns (workspace_dir, home_dir, ssh_temp, ssh_priv, exported_key_base64url).
/// The ssh_temp TempDir is also returned to keep it alive during the test.
fn setup_env_key_workspace() -> (TempDir, TempDir, TempDir, PathBuf, String) {
    let (workspace_dir, home_dir, ssh_temp, ssh_priv) = setup_workspace();

    let keystore_root = home_dir.path().join("keys");

    // Read active kid
    let kid = load_active_kid(TEST_MEMBER_HANDLE, &keystore_root)
        .expect("should load active kid")
        .expect("active kid should exist");

    // Load encrypted private key from keystore
    let private_key = load_private_key(&keystore_root, TEST_MEMBER_HANDLE, &kid)
        .expect("should load private key");

    // Read SSH public key content
    let ssh_pub_path = ssh_priv.with_extension("pub");
    let ssh_pub_content = std::fs::read_to_string(&ssh_pub_path)
        .expect("should read SSH public key")
        .trim()
        .to_string();

    // Decrypt using Ed25519DirectBackend
    let backend = Ed25519DirectBackend::new(&ssh_priv).expect("should load SSH key");
    let plaintext = decrypt_private_key(&private_key, &backend, &ssh_pub_content, false)
        .expect("should decrypt private key");

    // Export as portable key
    let password = SecretString::new(TEST_PASSWORD.to_string());
    let exported = export_private_key_portable(
        &plaintext,
        &private_key.protected.subject_handle,
        &private_key.protected.kid,
        &private_key.protected.created_at,
        &private_key.protected.expires_at,
        &password,
        false,
    )
    .expect("should export private key")
    .into_plain_string_for_output();

    (workspace_dir, home_dir, ssh_temp, ssh_priv, exported)
}

/// Build a CLI command configured for env key mode.
///
/// Note: `--workspace` is a subcommand option, so it must be added
/// after the subcommand arg by the caller.
fn env_key_cmd(home: &TempDir, exported_key: &str, password: &str) -> assert_cmd::Command {
    let mut c = cmd();
    c.env("SECRETENV_HOME", home.path())
        .env("SECRETENV_PRIVATE_KEY", exported_key)
        .env("SECRETENV_KEY_PASSWORD", password);
    // Remove SSH_AUTH_SOCK to ensure env key mode is used
    c.env_remove("SSH_AUTH_SOCK");
    c.env_remove("SECRETENV_SSH_IDENTITY");
    c
}

// ============================================================================
// Read-only Success Tests
// ============================================================================

#[test]
fn test_env_key_get_roundtrip() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv, exported_key) = setup_env_key_workspace();

    // Prepare the encrypted KV document in normal SSH mode.
    cmd()
        .arg("set")
        .arg("DATABASE_URL")
        .arg("postgres://localhost/testdb")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Read it back in env key mode.
    env_key_cmd(&home_dir, &exported_key, TEST_PASSWORD)
        .arg("get")
        .arg("DATABASE_URL")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("postgres://localhost/testdb"));
}

#[test]
fn test_env_key_decrypt_roundtrip() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv, exported_key) = setup_env_key_workspace();

    // Prepare the encrypted file in normal SSH mode.
    let original_content = b"TOP_SECRET=env_key_mode_works\n";
    let input_file = home_dir.path().join("secret.txt");
    fs::write(&input_file, original_content).unwrap();

    let encrypted_file = home_dir.path().join("secret.txt.encrypted");
    let decrypted_file = home_dir.path().join("decrypted.txt");

    cmd()
        .arg("encrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Decrypt in env key mode.
    env_key_cmd(&home_dir, &exported_key, TEST_PASSWORD)
        .arg("decrypt")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--out")
        .arg(decrypted_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .assert()
        .success();

    assert!(decrypted_file.exists(), "Decrypted file should exist");
    let decrypted_content = std::fs::read(&decrypted_file).unwrap();
    assert_eq!(
        decrypted_content, original_content,
        "Decrypted content should match original"
    );
}

#[test]
fn test_env_key_run_roundtrip() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv, exported_key) = setup_env_key_workspace();

    cmd()
        .arg("set")
        .arg("APP_TOKEN")
        .arg("run-mode-value")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    #[cfg(unix)]
    let mut c = env_key_cmd(&home_dir, &exported_key, TEST_PASSWORD);
    #[cfg(unix)]
    c.arg("run")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("echo $APP_TOKEN")
        .assert()
        .success()
        .stdout(predicate::str::contains("run-mode-value"));

    #[cfg(windows)]
    let mut c = env_key_cmd(&home_dir, &exported_key, TEST_PASSWORD);
    #[cfg(windows)]
    c.arg("run")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--")
        .arg("cmd")
        .arg("/c")
        .arg("echo %APP_TOKEN%")
        .assert()
        .success()
        .stdout(predicate::str::contains("run-mode-value"));
}

// ============================================================================
// Error Cases
// ============================================================================

#[test]
fn test_env_key_missing_password_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv, exported_key) = setup_env_key_workspace();

    cmd()
        .arg("set")
        .arg("SOME_KEY")
        .arg("some_value")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Set SECRETENV_PRIVATE_KEY but NOT SECRETENV_KEY_PASSWORD
    let mut c = cmd();
    c.env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_PRIVATE_KEY", &exported_key)
        .env_remove("SECRETENV_KEY_PASSWORD")
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("SECRETENV_SSH_IDENTITY");

    c.arg("get")
        .arg("SOME_KEY")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("SECRETENV_KEY_PASSWORD"));
}

#[test]
fn test_env_key_wrong_password_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv, exported_key) = setup_env_key_workspace();

    cmd()
        .arg("set")
        .arg("SOME_KEY")
        .arg("some_value")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Use wrong password
    env_key_cmd(&home_dir, &exported_key, "wrong-password-99")
        .arg("get")
        .arg("SOME_KEY")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .assert()
        .failure();
}

#[test]
fn test_env_key_mode_rejects_set() {
    let (workspace_dir, home_dir, _ssh_temp, _ssh_priv, exported_key) = setup_env_key_workspace();

    env_key_cmd(&home_dir, &exported_key, TEST_PASSWORD)
        .arg("set")
        .arg("SOME_KEY")
        .arg("some_value")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("environment-variable key mode"))
        .stderr(predicate::str::contains(ENV_MODE_UNSUPPORTED_MESSAGE));
}

#[test]
fn test_env_key_mode_rejects_encrypt() {
    let (workspace_dir, home_dir, _ssh_temp, _ssh_priv, exported_key) = setup_env_key_workspace();
    let input_file = home_dir.path().join("blocked.txt");
    fs::write(&input_file, b"blocked").unwrap();

    env_key_cmd(&home_dir, &exported_key, TEST_PASSWORD)
        .arg("encrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("environment-variable key mode"))
        .stderr(predicate::str::contains(ENV_MODE_UNSUPPORTED_MESSAGE));
}

#[test]
fn test_env_key_mode_rejects_rewrap() {
    let (workspace_dir, home_dir, _ssh_temp, _ssh_priv, exported_key) = setup_env_key_workspace();

    env_key_cmd(&home_dir, &exported_key, TEST_PASSWORD)
        .arg("rewrap")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("environment-variable key mode"))
        .stderr(predicate::str::contains(ENV_MODE_UNSUPPORTED_MESSAGE));
}

#[test]
fn test_env_key_mode_allows_list() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv, exported_key) = setup_env_key_workspace();

    cmd()
        .arg("set")
        .arg("LISTABLE_KEY")
        .arg("listable-value")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    env_key_cmd(&home_dir, &exported_key, TEST_PASSWORD)
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("LISTABLE_KEY"));
}

#[test]
fn test_env_key_mode_rejects_key_new() {
    let (_workspace_dir, home_dir, _ssh_temp, _ssh_priv, exported_key) = setup_env_key_workspace();

    env_key_cmd(&home_dir, &exported_key, TEST_PASSWORD)
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .assert()
        .failure()
        .stderr(predicate::str::contains("environment-variable key mode"))
        .stderr(predicate::str::contains(ENV_MODE_UNSUPPORTED_MESSAGE));
}

#[test]
fn test_env_key_mode_rejects_init() {
    let (workspace_dir, home_dir, _ssh_temp, _ssh_priv, exported_key) = setup_env_key_workspace();

    env_key_cmd(&home_dir, &exported_key, TEST_PASSWORD)
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .assert()
        .failure()
        .stderr(predicate::str::contains("environment-variable key mode"))
        .stderr(predicate::str::contains(ENV_MODE_UNSUPPORTED_MESSAGE));
}
