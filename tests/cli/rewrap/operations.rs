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
