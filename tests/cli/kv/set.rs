// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `set` command

use crate::cli::common::{cmd, setup_workspace, ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE};
use crate::test_utils::{
    setup_member_key_context, setup_test_workspace_from_fixtures, setup_trust_store_for_workspace,
};
use predicates::prelude::*;
use secretenv::format::kv::enc::canonical::parse_kv_wrap;
use secretenv::io::keystore::active::set_active_kid;
use secretenv::io::keystore::storage::list_kids;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_set_creates_new_file() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let default_file = workspace_dir.path().join("secrets").join("default.kvenc");

    // Set a key-value pair
    cmd()
        .arg("set")
        .arg("DATABASE_URL")
        .arg("postgres://localhost/db")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

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
    cmd()
        .arg("set")
        .arg("API_KEY")
        .arg("initial_value")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Update the value
    cmd()
        .arg("set")
        .arg("API_KEY")
        .arg("updated_value")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Verify the value was updated (by getting it)
    cmd()
        .arg("get")
        .arg("API_KEY")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("updated_value"));
}

#[test]
fn test_set_multiple_keys() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Set multiple keys
    cmd()
        .arg("set")
        .arg("KEY1")
        .arg("value1")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("set")
        .arg("KEY2")
        .arg("value2")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Verify both keys exist
    cmd()
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
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
        .env("SECRETENV_HOME", home_dir.path())
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
    cmd()
        .arg("set")
        .arg("SECRET_TOKEN")
        .arg("--stdin")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin("super-secret-token")
        .assert()
        .success();

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
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
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
        .env("SECRETENV_HOME", home_dir.path())
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
        .env("SECRETENV_HOME", home_dir.path())
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

    cmd()
        .arg("set")
        .arg("API_KEY")
        .arg("initial_value")
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .env("SECRETENV_HOME", home_dir)
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    fs::rename(&bob_incoming, &bob_active).unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&alice_kid));
    setup_trust_store_for_workspace(home_dir, &workspace_dir, ALICE_MEMBER_HANDLE, &key_ctx);

    cmd()
        .arg("set")
        .arg("API_KEY")
        .arg("updated_value")
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .env("SECRETENV_HOME", home_dir)
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

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

#[test]
fn test_set_existing_file_rejects_strict_key_checking_no() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    cmd()
        .arg("set")
        .arg("API_KEY")
        .arg("initial_value")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("set")
        .arg("API_KEY")
        .arg("updated_value")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .env("SECRETENV_STRICT_KEY_CHECKING", "no")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not allowed").and(predicate::str::contains("set")));
}

#[test]
fn test_set_new_file_rejects_strict_key_checking_no() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    cmd()
        .arg("set")
        .arg("API_KEY")
        .arg("initial_value")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .env("SECRETENV_STRICT_KEY_CHECKING", "no")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not allowed").and(predicate::str::contains("set")));
}
