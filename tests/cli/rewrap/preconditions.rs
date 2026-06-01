// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_utils::{
    build_expiring_soon_timestamp, save_active_public_key_to_workspace, setup_member_key_context,
    setup_trust_store_for_workspace, update_active_private_key_expires_at,
};
use console::strip_ansi_codes;

#[cfg(unix)]
use kapsaro_core::cli_api::test_support::storage::trust::paths::get_trust_store_file_path;

#[test]
fn test_rewrap_requires_workspace() {
    let (temp_dir, _workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = None;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let invalid_workspace = temp_dir.path().join("workspace-does-not-exist");
    let output = with_vars(
        [(
            "KAPSARO_WORKSPACE",
            Some(invalid_workspace.to_str().expect("invalid path as str")),
        )],
        || run_rewrap_command(&common_opts, ALICE_MEMBER_HANDLE, &[]),
    );

    assert!(!output.status.success(), "Should fail without workspace");
}

#[test]
fn test_rewrap_with_no_files_fails_gracefully() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let output = run_rewrap_command(&common_opts, ALICE_MEMBER_HANDLE, &[]);
    assert!(
        !output.status.success(),
        "Should fail with no files in secrets/"
    );

    let err_msg = String::from_utf8_lossy(&output.stderr);
    assert!(
        err_msg.contains("No encrypted files"),
        "Error should mention no files found: {}",
        err_msg
    );
}

#[test]
fn test_rewrap_nonexistent_workspace_fails() {
    let (_ssh_temp, ssh_priv, _ssh_pub, _pub_content) = generate_temp_ssh_keypair();
    let home_dir = tempfile::TempDir::new().unwrap();

    cmd()
        .arg("rewrap")
        .arg("--workspace")
        .arg("/tmp/nonexistent_workspace_kapsaro_test")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

#[test]
fn test_rewrap_quiet_keeps_failed_file_details_on_stderr() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) =
        setup_workspace_with_kv_entries(&[("BROKEN_KEY", "broken_value")]);
    let kv_path = workspace_dir.path().join("secrets").join("default.kvenc");
    tamper_kv_signature(&kv_path);

    let assert = cmd()
        .arg("rewrap")
        .arg("--quiet")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .env("CLICOLOR_FORCE", "1")
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("\u{1b}[31mError processing "),
        "expected colored failed file detail in stderr, got: {stderr}"
    );
    assert!(
        strip_ansi_codes(&stderr).contains("Signature verification failed"),
        "expected failure detail after stripping ANSI, got: {stderr}"
    );
    assert!(
        strip_ansi_codes(&stderr).contains("Failed to rewrap 1 file(s). See errors above."),
        "expected top-level rewrap failure after stripping ANSI, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_rewrap_surfaces_insecure_trust_store_warning_on_stderr() {
    use std::os::unix::fs::PermissionsExt;

    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    let trust_path = get_trust_store_file_path(temp_dir.path(), ALICE_MEMBER_HANDLE);
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    save_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_HANDLE,
        "warn_rewrap",
        &[("KEY", "value")],
    );

    let ssh_key = temp_dir.path().join(".ssh").join("test_ed25519");
    cmd()
        .arg("rewrap")
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .env("KAPSARO_HOME", temp_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_key)
        .assert()
        .success()
        .stderr(predicate::str::contains("Insecure permissions"));
}

#[test]
fn test_rewrap_surfaces_recipient_key_expiry_warning_on_stderr() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(temp_dir.path(), BOB_MEMBER_HANDLE, &expires_at);
    save_active_public_key_to_workspace(temp_dir.path(), &workspace_dir, BOB_MEMBER_HANDLE)
        .unwrap();
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

    save_kv_file(
        &workspace_dir,
        common_opts,
        ALICE_MEMBER_HANDLE,
        "recipient_expiry",
        &[("KEY", "value")],
    );

    let ssh_key = temp_dir.path().join(".ssh").join("test_ed25519");
    cmd()
        .arg("rewrap")
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .env("KAPSARO_HOME", temp_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_key)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Warning: Recipient public key for 'bob@example.com' expires in",
        ));
}
