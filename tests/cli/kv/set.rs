// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `set` command

use crate::cli::common::{
    cmd, set_stdin_with_member_set_review, set_value_with_member_set_review, setup_workspace,
    ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE,
};
use crate::test_utils::{
    setup_member_key_context, setup_test_workspace_from_fixtures, setup_trust_store_for_workspace,
};
use kapsaro_core::cli_api::test_support::storage::keystore::active::set_active_kid;
use kapsaro_core::cli_api::test_support::storage::keystore::storage::list_kids;
use kapsaro_core::cli_api::test_support::wire::kv::enc::canonical::parse_kv_wrap;
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

    // Verify file content
    let content = fs::read_to_string(&default_file).unwrap();
    assert!(content.contains("DATABASE_URL"), "File should contain key");
}

#[test]
fn test_set_updates_existing_key() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Set initial value
    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "API_KEY",
        "initial_value",
        None,
        None,
    );

    // Update the value
    cmd()
        .arg("set")
        .arg("API_KEY")
        .arg("updated_value")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Verify the value was updated (by getting it)
    cmd()
        .arg("get")
        .arg("API_KEY")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("updated_value"));
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
fn test_set_multiple_keys() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Set multiple keys
    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "KEY1",
        "value1",
        None,
        None,
    );

    cmd()
        .arg("set")
        .arg("KEY2")
        .arg("value2")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Verify both keys exist
    cmd()
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("KEY1"))
        .stdout(predicate::str::contains("KEY2"));
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

#[test]
fn test_set_existing_file_updates_wrap_to_current_active_members() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let home_dir = temp_dir.path();
    let ssh_priv = temp_dir.path().join(".ssh").join("test_ed25519");
    let keystore_root = temp_dir.path().join("keys");
    let alice_kid = list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    set_active_kid(ALICE_MEMBER_HANDLE, &alice_kid, &keystore_root).unwrap();
    let bob_active = workspace_dir
        .join("members")
        .join("active")
        .join(format!("{}.json", BOB_MEMBER_HANDLE));
    let bob_incoming = workspace_dir
        .join("members")
        .join("incoming")
        .join(format!("{}.json", BOB_MEMBER_HANDLE));
    fs::rename(&bob_active, &bob_incoming).unwrap();

    set_value_with_member_set_review(
        &workspace_dir,
        home_dir,
        &ssh_priv,
        "API_KEY",
        "initial_value",
        Some(ALICE_MEMBER_HANDLE),
        None,
    );

    fs::rename(&bob_incoming, &bob_active).unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&alice_kid));
    setup_trust_store_for_workspace(home_dir, &workspace_dir, ALICE_MEMBER_HANDLE, &key_ctx);

    set_value_with_member_set_review(
        &workspace_dir,
        home_dir,
        &ssh_priv,
        "API_KEY",
        "updated_value",
        Some(ALICE_MEMBER_HANDLE),
        None,
    );

    let kv_path = workspace_dir.join("secrets").join("default.kvenc");
    let content = fs::read_to_string(kv_path).unwrap();
    let (_, _, wrap) = parse_kv_wrap(&content).unwrap();
    let mut recipient_handles = wrap
        .wrap
        .iter()
        .map(|item| item.recipient_handle.clone())
        .collect::<Vec<_>>();
    recipient_handles.sort();
    assert_eq!(
        recipient_handles,
        vec![
            ALICE_MEMBER_HANDLE.to_string(),
            BOB_MEMBER_HANDLE.to_string()
        ]
    );
}
