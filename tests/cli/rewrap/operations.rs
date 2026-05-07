// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_utils::{setup_member_key_context, setup_trust_store_for_workspace};

#[test]
fn test_rewrap_rotate_key() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let kv_path = save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_HANDLE,
        "test_rotate",
        &[("KEY", "value")],
    );

    let content_before = fs::read_to_string(&kv_path).unwrap();

    run_rewrap_with_member_set_review_args(&common_opts, ALICE_MEMBER_HANDLE, &["--rotate-key"]);

    let content_after = fs::read_to_string(&kv_path).unwrap();
    assert_ne!(
        content_before, content_after,
        "File content should change after rotate_key"
    );

    let recipient_handles_after = load_kv_recipient_handles(&kv_path);
    assert!(
        recipient_handles_after.contains(&ALICE_MEMBER_HANDLE.to_string()),
        "ALICE should still be in wrap after rotate_key"
    );
}

#[test]
fn test_rewrap_noop_rewrites_file() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let kv_path = save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_HANDLE,
        "test_noop",
        &[("KEY", "value")],
    );

    let rewrap_args = default_rewrap_args(common_opts.clone(), ALICE_MEMBER_HANDLE);
    let result = rewrap::run(rewrap_args);
    assert!(
        result.is_ok(),
        "Rewrap noop should succeed: {:?}",
        result.err()
    );

    assert!(
        kv_path.exists(),
        "File should still exist after noop rewrap"
    );
    let recipient_handles = load_kv_recipient_handles(&kv_path);
    assert!(
        recipient_handles.contains(&ALICE_MEMBER_HANDLE.to_string()),
        "ALICE should still be in wrap after noop rewrap"
    );
}

#[test]
fn test_rewrap_clear_disclosure_history() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let kv_path = save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_HANDLE,
        "test_clear_history",
        &[("KEY", "value")],
    );

    fs::remove_file(
        workspace_dir
            .join("members/active")
            .join(format!("{}.json", BOB_MEMBER_HANDLE)),
    )
    .unwrap();

    run_rewrap_with_member_set_review(&common_opts, ALICE_MEMBER_HANDLE);

    let removed = load_kv_removed_recipient_handles(&kv_path);
    assert!(
        removed.contains(&BOB_MEMBER_HANDLE.to_string()),
        "BOB should be in removed_recipients after first rewrap: {:?}",
        removed
    );

    let mut rewrap_args = default_rewrap_args(common_opts.clone(), ALICE_MEMBER_HANDLE);
    rewrap_args.clear_disclosure_history = true;
    let result = rewrap::run(rewrap_args);
    assert!(
        result.is_ok(),
        "Rewrap with clear_disclosure_history should succeed: {:?}",
        result.err()
    );

    let removed_after = load_kv_removed_recipient_handles(&kv_path);
    assert!(
        removed_after.is_empty(),
        "removed_recipients should be empty after clear_disclosure_history: {:?}",
        removed_after
    );
}

#[test]
fn test_rewrap_with_rotate_key_flag() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "ROTATE_TEST",
        "value123",
        Some(TEST_MEMBER_HANDLE),
        None,
    );

    let mut command = crate::cli::common::secretenv_std_cmd();
    command
        .arg("rewrap")
        .arg("--rotate-key")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", &ssh_priv);
    crate::cli::common::assert_member_set_review_success(&mut command);

    cmd()
        .arg("get")
        .arg("ROTATE_TEST")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("value123"));
}

#[test]
fn test_rewrap_with_clear_disclosure_history_flag() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "HISTORY_TEST",
        "histval",
        Some(TEST_MEMBER_HANDLE),
        None,
    );

    cmd()
        .arg("rewrap")
        .arg("--clear-disclosure-history")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();
}
