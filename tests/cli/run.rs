// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `run` command

use crate::cli::common::{
    cmd, generate_temp_ssh_keypair, make_secret_home, set_value_with_member_set_review,
    setup_workspace, tamper_kv_signature, TEST_MEMBER_HANDLE,
};
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper to create a workspace with initialized member, a key, and default kv-enc file
fn setup_workspace_with_default_file() -> (TempDir, TempDir, TempDir, PathBuf) {
    let (workspace_dir, home_dir, ssh_temp, ssh_priv) = setup_workspace();

    // Set a key to create default.kvenc
    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "TEST_KEY",
        "test_value",
        None,
        None,
    );

    (workspace_dir, home_dir, ssh_temp, ssh_priv)
}

#[test]
fn test_run_error_when_workspace_not_found() {
    let home_dir = make_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    // Try to run without workspace (should fail)
    cmd()
        // Ensure workspace auto-detection cannot accidentally succeed
        .current_dir(home_dir.path())
        .arg("run")
        .arg("--")
        .arg("echo")
        .arg("test")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("workspace")
                .or(predicate::str::contains("not found"))
                .or(predicate::str::contains("member handle not configured")),
        );

    drop(ssh_temp);
}

#[test]
fn test_run_error_when_default_file_not_exists() {
    let workspace_dir = TempDir::new().unwrap();
    let home_dir = make_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    // Create workspace structure
    fs::create_dir_all(workspace_dir.path().join("members")).unwrap();
    fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();

    // Run init to register member
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

    // Try to run without default file (should fail)
    cmd()
        .arg("run")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--")
        .arg("echo")
        .arg("test")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found").or(predicate::str::contains("default")));

    drop(ssh_temp);
}

#[test]
fn test_run_with_multiple_env_vars() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_default_file();

    // Add more keys
    cmd()
        .arg("set")
        .arg("DATABASE_URL")
        .arg("postgres://localhost")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("set")
        .arg("API_KEY")
        .arg("secret123")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Run command that checks multiple environment variables
    #[cfg(unix)]
    let test_cmd = "sh";
    #[cfg(unix)]
    let test_args = vec!["-c", "echo $TEST_KEY:$DATABASE_URL:$API_KEY"];

    #[cfg(windows)]
    let test_cmd = "cmd";
    #[cfg(windows)]
    let test_args = vec!["/c", "echo %TEST_KEY%:%DATABASE_URL%:%API_KEY%"];

    let mut run_cmd = cmd();
    run_cmd
        .arg("run")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--")
        .arg(test_cmd);
    for arg in test_args {
        run_cmd.arg(arg);
    }
    run_cmd
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(
            predicate::str::contains("test_value")
                .and(predicate::str::contains("postgres://localhost"))
                .and(predicate::str::contains("secret123")),
        );
}

#[cfg(unix)]
#[test]
fn test_run_rejects_tampered_kv_signature() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_default_file();
    let kv_path = workspace_dir.path().join("secrets").join("default.kvenc");
    tamper_kv_signature(&kv_path);

    cmd()
        .arg("run")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("echo should-not-run")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stdout(predicate::str::contains("should-not-run").not())
        .stderr(predicate::str::contains("Signature verification failed"));
}

#[test]
fn test_run_nonexistent_command_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_default_file();

    cmd()
        .arg("run")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--")
        .arg("nonexistent_command_xyz_12345")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

#[test]
fn test_run_no_command_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_default_file();

    cmd()
        .arg("run")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

#[test]
fn test_run_preserves_exit_code() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_default_file();

    cmd()
        .arg("run")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("exit 42")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .code(42);
}

#[cfg(unix)]
#[test]
fn test_run_inherits_nonstandard_parent_env() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_default_file();

    cmd()
        .arg("run")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("printf %s \"$LEAK_ME\"")
        .env("LEAK_ME", "top-secret")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("top-secret"));
}

#[cfg(unix)]
#[test]
fn test_run_does_not_inherit_secretenv_parent_env() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_default_file();

    cmd()
        .arg("run")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg(
            "test -z \"$SECRETENV_HOME\" && \
             test -z \"$SECRETENV_SSH_IDENTITY\" && \
             test -z \"$SECRETENV_SSH_SIGNING_METHOD\" && \
             test -z \"$SECRETENV_CUSTOM\" && \
             echo absent",
        )
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .env("SECRETENV_CUSTOM", "parent-secret")
        .assert()
        .success()
        .stdout(predicate::str::contains("absent"));
}

#[cfg(unix)]
#[test]
fn test_run_preserves_standard_env_vars() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_default_file();

    cmd()
        .arg("run")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("test -n \"$PATH\" && test -n \"$HOME\" && echo ok")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("ok"));
}

#[cfg(unix)]
#[test]
fn test_run_secret_env_overrides_standard_env_vars() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace_with_default_file();

    cmd()
        .arg("set")
        .arg("PATH")
        .arg("secret_path")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("run")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("printf %s \"$PATH\"")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("secret_path"));
}
