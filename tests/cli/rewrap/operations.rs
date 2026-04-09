// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_utils::{setup_member_key_context, setup_trust_store_for_workspace};

#[test]
fn test_rewrap_rotate_key() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let kv_path = create_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_ID,
        "test_rotate",
        &[("KEY", "value")],
    );

    let content_before = fs::read_to_string(&kv_path).unwrap();

    let mut rewrap_args = default_rewrap_args(common_opts.clone(), ALICE_MEMBER_ID);
    rewrap_args.rotate_key = true;
    let result = rewrap::run(rewrap_args);
    assert!(
        result.is_ok(),
        "Rewrap with rotate_key should succeed: {:?}",
        result.err()
    );

    let content_after = fs::read_to_string(&kv_path).unwrap();
    assert_ne!(
        content_before, content_after,
        "File content should change after rotate_key"
    );

    let rids_after = get_kv_rids(&kv_path);
    assert!(
        rids_after.contains(&ALICE_MEMBER_ID.to_string()),
        "ALICE should still be in wrap after rotate_key"
    );
}

#[test]
fn test_rewrap_noop_rewrites_file() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let kv_path = create_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_ID,
        "test_noop",
        &[("KEY", "value")],
    );

    let rewrap_args = default_rewrap_args(common_opts.clone(), ALICE_MEMBER_ID);
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
    let rids = get_kv_rids(&kv_path);
    assert!(
        rids.contains(&ALICE_MEMBER_ID.to_string()),
        "ALICE should still be in wrap after noop rewrap"
    );
}

#[test]
fn test_rewrap_clear_disclosure_history() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let kv_path = create_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_ID,
        "test_clear_history",
        &[("KEY", "value")],
    );

    fs::remove_file(
        workspace_dir
            .join("members/active")
            .join(format!("{}.json", BOB_MEMBER_ID)),
    )
    .unwrap();

    let rewrap_args = default_rewrap_args(common_opts.clone(), ALICE_MEMBER_ID);
    rewrap::run(rewrap_args).unwrap();

    let removed = get_kv_removed_rids(&kv_path);
    assert!(
        removed.contains(&BOB_MEMBER_ID.to_string()),
        "BOB should be in removed_recipients after first rewrap: {:?}",
        removed
    );

    let mut rewrap_args2 = default_rewrap_args(common_opts.clone(), ALICE_MEMBER_ID);
    rewrap_args2.clear_disclosure_history = true;
    let result = rewrap::run(rewrap_args2);
    assert!(
        result.is_ok(),
        "Rewrap with clear_disclosure_history should succeed: {:?}",
        result.err()
    );

    let removed_after = get_kv_removed_rids(&kv_path);
    assert!(
        removed_after.is_empty(),
        "removed_recipients should be empty after clear_disclosure_history: {:?}",
        removed_after
    );
}

#[test]
fn test_rewrap_with_rotate_key_flag() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    cmd()
        .arg("set")
        .arg("ROTATE_TEST")
        .arg("value123")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("rewrap")
        .arg("--rotate-key")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("get")
        .arg("ROTATE_TEST")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("value123"));
}

#[test]
fn test_rewrap_with_clear_disclosure_history_flag() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    cmd()
        .arg("set")
        .arg("HISTORY_TEST")
        .arg("histval")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("rewrap")
        .arg("--clear-disclosure-history")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success();
}
