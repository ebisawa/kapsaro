// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::setup_init_env;
use crate::cli::common::{cmd, TEST_MEMBER_HANDLE};
use crate::test_utils::EnvGuard;
use predicates::prelude::*;
use std::fs;

#[test]
fn test_init_generates_key_if_missing() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_init_env();

    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    let keystore_path = home_dir.path().join("keys").join(TEST_MEMBER_HANDLE);
    assert!(keystore_path.exists());

    let key_dirs: Vec<_> = fs::read_dir(&keystore_path)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .collect();
    assert!(!key_dirs.is_empty());
}

#[test]
fn test_init_with_debug_option_logs_crypto_trace() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_init_env();

    cmd()
        .arg("init")
        .arg("--debug")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg("debug@example.com")
        .env("SECRETENV_HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("[CRYPTO] SSH: sign_sshsig"));
}

#[test]
fn test_init_with_verbose_option_does_not_log_crypto_trace() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_init_env();

    cmd()
        .arg("init")
        .arg("--verbose")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg("verbose@example.com")
        .env("SECRETENV_HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("[CRYPTO] SSH: sign_sshsig").not());
}

#[test]
fn test_init_uses_existing_key() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME"]);
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_init_env();

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success();

    std::env::set_var("SECRETENV_HOME", home_dir.path().to_str().unwrap());
    let base_dir =
        secretenv_core::cli_api::test_support::storage::config::paths::get_base_dir().unwrap();
    let member_dir =
        secretenv_core::cli_api::test_support::storage::keystore::paths::get_keystore_root_from_base(
            &base_dir,
        )
        .join(TEST_MEMBER_HANDLE);
    let kids_before: Vec<_> = fs::read_dir(&member_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_str().unwrap().to_string())
        .collect();

    assert_eq!(kids_before.len(), 1);

    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    let kids_after: Vec<_> = fs::read_dir(&member_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_str().unwrap().to_string())
        .collect();

    assert_eq!(kids_after.len(), 1);
    assert_eq!(kids_before, kids_after);
}
