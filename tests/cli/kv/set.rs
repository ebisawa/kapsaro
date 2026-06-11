// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `set` command

use crate::cli::common::{
    cmd, set_stdin_with_member_set_review, set_value_with_member_set_review, setup_workspace,
};
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
fn test_set_debug_does_not_log_secret_value() {
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

#[test]
fn test_set_without_workspace_fails() {
    let home_dir = TempDir::new().unwrap();

    // workspace を設定せずに set を実行 → エラーになることを確認
    cmd()
        .arg("set")
        .arg("DATABASE_URL")
        .arg("postgres://localhost/db")
        .env("KAPSARO_HOME", home_dir.path())
        .current_dir("/tmp")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("SSH key")
                .or(predicate::str::contains("workspace"))
                .or(predicate::str::contains("member handle not configured")),
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
