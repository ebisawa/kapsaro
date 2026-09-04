// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `set` command

use crate::cli::common::{
    cmd, kapsaro_std_cmd, run_command_with_pty, set_stdin_with_member_set_review,
    set_value_with_member_set_review, setup_workspace, ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE,
};
use crate::test_utils::setup_trust_store_for_workspace;
use kapsaro_test_support::crypto_context::setup_member_key_context;
use kapsaro_test_support::fixture::setup_test_workspace;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_set_creates_new_file() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let default_file = workspace_dir.path().join("secrets").join("default.kvenc");

    // Set a key-value pair
    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "DATABASE_URL",
        "postgres://localhost/db",
        None,
        None,
    );

    // Verify file was created
    assert!(default_file.exists(), "Default file should be created");
}

#[test]
fn test_set_debug_logs_without_the_secret_value() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "BOOTSTRAP_KEY",
        "bootstrap_value",
        None,
        None,
    );

    cmd()
        .arg("set")
        .arg("API_TOKEN")
        .arg("do-not-log-this-token")
        .arg("--debug")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("RUST_LOG", "warn")
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("[CLI] command=set"))
        .stdout(predicate::str::contains("[TRUST] write gate:"))
        .stdout(predicate::str::contains("do-not-log-this-token").not());
}

#[cfg(unix)]
#[test]
fn test_set_after_approving_recipient_key_in_same_command() {
    let (home_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let key_ctx = setup_member_key_context(&home_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        home_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );
    let ssh_identity = home_dir.path().join(".ssh").join("test_ed25519");

    set_value_with_member_set_review(
        &workspace_dir,
        home_dir.path(),
        &ssh_identity,
        "EXISTING_KEY",
        "existing-value",
        Some(ALICE_MEMBER_HANDLE),
        None,
    );

    let bob_member: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(
            workspace_dir
                .join("members")
                .join("active")
                .join(format!("{BOB_MEMBER_HANDLE}.json")),
        )
        .unwrap(),
    )
    .unwrap();
    let bob_kid = bob_member["protected"]["kid"].as_str().unwrap();
    cmd()
        .arg("trust")
        .arg("keys")
        .arg("remove")
        .arg(bob_kid)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(&workspace_dir)
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", &ssh_identity)
        .assert()
        .success();

    let mut command = kapsaro_std_cmd();
    command
        .arg("set")
        .arg("NEW_KEY")
        .arg("new-value")
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(&workspace_dir)
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", &ssh_identity);
    let result = run_command_with_pty(&mut command, "Approve this key?", b"y\r");
    assert!(
        result.status.success(),
        "set should continue after approving Bob's recipient key:\n{}",
        result.output
    );

    cmd()
        .arg("get")
        .arg("NEW_KEY")
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(&workspace_dir)
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", &ssh_identity)
        .assert()
        .success()
        .stdout(predicate::str::ends_with("new-value\n"));
}

#[cfg(unix)]
#[test]
fn test_set_existing_kv_approves_recipient_set_before_update() {
    let (home_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let key_ctx = setup_member_key_context(&home_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        home_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );
    let ssh_identity = home_dir.path().join(".ssh").join("test_ed25519");
    set_value_with_member_set_review(
        &workspace_dir,
        home_dir.path(),
        &ssh_identity,
        "KEY",
        "old",
        Some(ALICE_MEMBER_HANDLE),
        None,
    );
    remove_first_recipient_set(home_dir.path(), &ssh_identity);

    let mut command = existing_set_command(&workspace_dir, home_dir.path(), &ssh_identity, "new");
    let result = run_command_with_pty(&mut command, "Trust this member set", b"y\r");

    assert!(result.status.success(), "set failed:\n{}", result.output);
    assert!(result.output.contains(BOB_MEMBER_HANDLE));
    assert!(!result.output.contains("unknown"));
}

#[cfg(unix)]
#[test]
fn test_set_existing_kv_rejects_recipient_set_without_update() {
    let (home_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let key_ctx = setup_member_key_context(&home_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        home_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );
    let ssh_identity = home_dir.path().join(".ssh").join("test_ed25519");
    set_value_with_member_set_review(
        &workspace_dir,
        home_dir.path(),
        &ssh_identity,
        "KEY",
        "old",
        Some(ALICE_MEMBER_HANDLE),
        None,
    );
    remove_first_recipient_set(home_dir.path(), &ssh_identity);
    let path = workspace_dir.join("secrets").join("default.kvenc");
    let before = fs::read_to_string(&path).unwrap();

    let mut command = existing_set_command(&workspace_dir, home_dir.path(), &ssh_identity, "new");
    let result = run_command_with_pty(&mut command, "Trust this member set", b"n\r");

    assert!(!result.status.success());
    assert!(result.output.contains("approval declined"));
    assert_eq!(fs::read_to_string(path).unwrap(), before);
}

#[cfg(unix)]
fn existing_set_command(
    workspace: &std::path::Path,
    home: &std::path::Path,
    ssh_identity: &std::path::Path,
    value: &str,
) -> std::process::Command {
    let mut command = kapsaro_std_cmd();
    command
        .arg("set")
        .arg("KEY")
        .arg(value)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace)
        .env("KAPSARO_HOME", home)
        .env("KAPSARO_SSH_IDENTITY", ssh_identity);
    command
}

#[cfg(unix)]
fn remove_first_recipient_set(home: &std::path::Path, ssh_identity: &std::path::Path) {
    let output = cmd()
        .arg("trust")
        .arg("recipients")
        .arg("list")
        .arg("--json")
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .arg("--home")
        .arg(home)
        .output()
        .unwrap();
    assert!(output.status.success());
    let start = output.stdout.iter().position(|byte| *byte == b'{').unwrap();
    let end = output
        .stdout
        .iter()
        .rposition(|byte| *byte == b'}')
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&output.stdout[start..=end]).unwrap();
    let sid = value["recipient_sets"][0]["sid"].as_str().unwrap();
    cmd()
        .arg("trust")
        .arg("recipients")
        .arg("remove")
        .arg(sid)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .arg("--home")
        .arg(home)
        .arg("--ssh-identity")
        .arg(ssh_identity)
        .assert()
        .success();
}

#[test]
fn test_set_without_workspace_fails() {
    let home_dir = TempDir::new().unwrap();
    let current_dir = TempDir::new().unwrap();

    // Run set without any workspace configuration.
    cmd()
        .arg("set")
        .arg("DATABASE_URL")
        .arg("postgres://localhost/db")
        .env("KAPSARO_HOME", home_dir.path())
        .env_remove("KAPSARO_MEMBER_HANDLE")
        .env_remove("KAPSARO_WORKSPACE")
        .env_remove("KAPSARO_PRIVATE_KEY")
        .current_dir(current_dir.path())
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("Error: workspace not found.\nReason:")
                .and(predicate::str::contains("kapsaro init"))
                .and(predicate::str::contains("\nOptions:\n1."))
                .and(predicate::str::contains("--workspace <path>"))
                .and(predicate::str::contains("member handle not configured").not()),
        );
}

#[test]
fn test_set_stdin_creates_new_file() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Set a key-value pair via --stdin
    set_stdin_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "SECRET_TOKEN",
        b"super-secret-token",
        None,
        None,
    );

    // Verify file was created and key exists
    let default_file = workspace_dir.path().join("secrets").join("default.kvenc");
    assert!(default_file.exists(), "Default file should be created");
    let content = fs::read_to_string(&default_file).unwrap();
    assert!(content.contains("SECRET_TOKEN"), "File should contain key");

    // Verify the value can be retrieved
    cmd()
        .arg("get")
        .arg("SECRET_TOKEN")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("super-secret-token"));
}

#[test]
fn test_set_stdin_and_value_arg_conflicts() {
    let home_dir = TempDir::new().unwrap();

    // --stdin と VALUE 引数の両方を指定するとエラー
    cmd()
        .arg("set")
        .arg("KEY")
        .arg("some_value")
        .arg("--stdin")
        .env("KAPSARO_HOME", home_dir.path())
        .current_dir("/tmp")
        .write_stdin("stdin_value")
        .assert()
        .failure();
}

#[test]
fn test_set_without_stdin_and_without_value_fails() {
    let home_dir = TempDir::new().unwrap();

    // VALUE も --stdin も指定しないとエラー
    cmd()
        .arg("set")
        .arg("KEY")
        .env("KAPSARO_HOME", home_dir.path())
        .current_dir("/tmp")
        .assert()
        .failure();
}
