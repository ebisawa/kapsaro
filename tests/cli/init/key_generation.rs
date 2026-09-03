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
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
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
fn test_init_invalid_github_user_before_ssh_resolution_fails() {
    let (workspace_dir, home_dir, _ssh_temp, _ssh_priv) = setup_init_env();
    let missing_identity = home_dir.path().join("missing-identity");
    let member_dir = home_dir.path().join("keys").join(TEST_MEMBER_HANDLE);
    let workspace_member = workspace_dir
        .path()
        .join("members")
        .join("active")
        .join(format!("{TEST_MEMBER_HANDLE}.json"));

    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--github-user")
        .arg("alice/keys")
        .arg("--ssh-identity")
        .arg(&missing_identity)
        .env("KAPSARO_HOME", home_dir.path())
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("GitHub login")
                .and(predicate::str::contains("SSH identity").not()),
        );

    assert!(
        !member_dir.exists(),
        "invalid login must not generate a key"
    );
    assert!(
        !member_dir.join("active").exists(),
        "invalid login must not activate a key"
    );
    assert!(
        !workspace_member.exists(),
        "invalid login must not register a workspace member"
    );
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
        .env("KAPSARO_HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("[CRYPTO] SSH: sign_sshsig"));
}

#[test]
fn test_init_with_rust_log_debug_logs_crypto_trace() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_init_env();

    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg("rust-log-debug@example.com")
        .env("KAPSARO_HOME", home_dir.path())
        .env("RUST_LOG", "debug")
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
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
        .env("KAPSARO_HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("[CRYPTO] SSH: sign_sshsig").not());
}

#[test]
fn test_init_uses_existing_key() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME"]);
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_init_env();

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("KAPSARO_HOME", home_dir.path())
        .assert()
        .success();

    std::env::set_var("KAPSARO_HOME", home_dir.path().to_str().unwrap());
    let base_dir = kapsaro_core::test_support::storage::config::paths::get_base_dir().unwrap();
    let member_dir =
        kapsaro_core::test_support::storage::keystore::paths::get_keystore_root_from_base(
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
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
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
