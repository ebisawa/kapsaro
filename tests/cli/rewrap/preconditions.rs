// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_utils::{
    build_expiring_soon_timestamp, setup_member_key_context, setup_trust_store_for_workspace,
    sync_active_public_key_to_workspace, update_active_private_key_expires_at,
};

#[cfg(unix)]
use secretenv::io::trust::paths::trust_store_file_path;

#[test]
fn test_rewrap_requires_workspace() {
    let (temp_dir, _workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = None;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let rewrap_args = default_rewrap_args(common_opts, ALICE_MEMBER_ID);
    let invalid_workspace = temp_dir.path().join("workspace-does-not-exist");
    let result = with_vars(
        [(
            "SECRETENV_WORKSPACE",
            Some(invalid_workspace.to_str().expect("invalid path as str")),
        )],
        || rewrap::run(rewrap_args),
    );

    assert!(result.is_err(), "Should fail without workspace");
}

#[test]
fn test_rewrap_with_no_files_fails_gracefully() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    let rewrap_args = default_rewrap_args(common_opts, ALICE_MEMBER_ID);
    let result = rewrap::run(rewrap_args);
    assert!(result.is_err(), "Should fail with no files in secrets/");

    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("No encrypted files"),
        "Error should mention no files found: {}",
        err_msg
    );
}

#[test]
fn test_rewrap_nonexistent_workspace_fails() {
    let (_ssh_temp, ssh_priv, _ssh_pub, _pub_content) = create_temp_ssh_keypair();
    let home_dir = tempfile::TempDir::new().unwrap();

    cmd()
        .arg("rewrap")
        .arg("--workspace")
        .arg("/tmp/nonexistent_workspace_secretenv_test")
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

#[test]
fn test_rewrap_help() {
    cmd()
        .arg("rewrap")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("rewrap"));
}

#[cfg(unix)]
#[test]
fn test_rewrap_surfaces_insecure_trust_store_warning_on_stderr() {
    use std::os::unix::fs::PermissionsExt;

    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let trust_path = trust_store_file_path(temp_dir.path(), ALICE_MEMBER_ID);
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    create_kv_file(
        &workspace_dir,
        common_opts.clone(),
        ALICE_MEMBER_ID,
        "warn_rewrap",
        &[("KEY", "value")],
    );

    let ssh_key = temp_dir.path().join(".ssh").join("test_ed25519");
    cmd()
        .arg("rewrap")
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--member-id")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", temp_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_key)
        .assert()
        .success()
        .stderr(predicate::str::contains("Insecure permissions"));
}

#[test]
fn test_rewrap_cli_rejects_strict_key_checking_no() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    create_kv_file(
        &workspace_dir,
        common_opts,
        ALICE_MEMBER_ID,
        "strict_no",
        &[("KEY", "value")],
    );

    let ssh_key = temp_dir.path().join(".ssh").join("test_ed25519");
    cmd()
        .arg("rewrap")
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--member-id")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", temp_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_key)
        .env("SECRETENV_STRICT_KEY_CHECKING", "no")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "SECRETENV_STRICT_KEY_CHECKING=no is not allowed for rewrap",
        ));
}

#[test]
fn test_rewrap_surfaces_recipient_key_expiry_warning_on_stderr() {
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, BOB_MEMBER_ID]);
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(temp_dir.path(), BOB_MEMBER_ID, &expires_at);
    sync_active_public_key_to_workspace(temp_dir.path(), &workspace_dir, BOB_MEMBER_ID).unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    setup_trust_store_for_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_ID, &key_ctx);

    let mut common_opts = default_common_options();
    common_opts.home = Some(temp_dir.path().to_path_buf());
    common_opts.workspace = Some(workspace_dir.clone());
    common_opts.quiet = true;
    set_ssh_key_from_temp_dir(&mut common_opts, &temp_dir);

    create_kv_file(
        &workspace_dir,
        common_opts,
        ALICE_MEMBER_ID,
        "recipient_expiry",
        &[("KEY", "value")],
    );

    let ssh_key = temp_dir.path().join(".ssh").join("test_ed25519");
    cmd()
        .arg("rewrap")
        .arg("--workspace")
        .arg(&workspace_dir)
        .arg("--member-id")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", temp_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_key)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Warning: Recipient public key for 'bob@example.com' expires in",
        ));
}
