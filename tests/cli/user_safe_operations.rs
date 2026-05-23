// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Release-candidate E2E coverage for user-safe operational flows.

use crate::cli::common::{
    assert_member_set_review_success, cmd, copy_dir_all, encrypt_file_with_member_set_review,
    import_file_with_member_set_review, make_secret_home, run_command_with_pty,
    run_command_with_pty_script, secretenv_std_cmd, set_value_with_member_set_review,
    setup_workspace, BOB_MEMBER_HANDLE, TEST_MEMBER_HANDLE,
};
use predicates::prelude::*;
use std::fs;
use std::path::Path;
use std::process::Command as StdCommand;
use tempfile::TempDir;

const CI_KEY_PASSWORD: &str = "ci-e2e-password-2026";

#[cfg(unix)]
#[test]
fn test_user_safe_daily_kv_and_run_flow_e2e() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let env_file = workspace_dir.path().join(".env");
    fs::write(
        &env_file,
        "DATABASE_URL=postgres://localhost/app\nAPI_KEY=initial-key\nOLD_KEY=remove-me\n",
    )
    .unwrap();

    let import_output = import_file_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        &env_file,
        false,
    );
    assert!(
        import_output.contains("Imported 3 entries"),
        "{import_output}"
    );

    assert_get_contains(
        &workspace_dir,
        &home_dir,
        &ssh_priv,
        "DATABASE_URL",
        "localhost/app",
    );
    assert_list_contains(&workspace_dir, &home_dir, &ssh_priv, "OLD_KEY");

    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "APP_TOKEN",
        "run-token",
        Some(TEST_MEMBER_HANDLE),
        None,
    );

    cmd()
        .arg("unset")
        .arg("OLD_KEY")
        .arg("--force")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("get")
        .arg("OLD_KEY")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();

    cmd()
        .arg("run")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("printf %s \"$APP_TOKEN\"")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("run-token"));
}

#[cfg(unix)]
#[test]
fn test_user_safe_member_add_offboarding_and_secret_rotation_e2e() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "SERVICE_TOKEN",
        "before-offboarding",
        Some(TEST_MEMBER_HANDLE),
        None,
    );

    let bob_public_key = home_dir.path().join("bob-public.json");
    add_bob_to_incoming(&workspace_dir, &home_dir, &ssh_priv, &bob_public_key);
    approve_rewrap_with_new_member(&workspace_dir, &home_dir, &ssh_priv);
    approve_member_key(
        &workspace_dir,
        &home_dir,
        &ssh_priv,
        BOB_MEMBER_HANDLE,
        TEST_MEMBER_HANDLE,
    );

    assert_get_as_member_contains(
        &workspace_dir,
        &home_dir,
        &ssh_priv,
        BOB_MEMBER_HANDLE,
        "SERVICE_TOKEN",
        "before-offboarding",
    );

    cmd()
        .arg("member")
        .arg("remove")
        .arg(BOB_MEMBER_HANDLE)
        .arg("--force")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    approve_rewrap_member_set(&workspace_dir, &home_dir, &ssh_priv);

    cmd()
        .arg("get")
        .arg("SERVICE_TOKEN")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(BOB_MEMBER_HANDLE)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .env("SECRETENV_STRICT_KEY_CHECKING", "no")
        .assert()
        .failure();

    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "SERVICE_TOKEN",
        "after-offboarding",
        Some(TEST_MEMBER_HANDLE),
        None,
    );
    assert_get_contains(
        &workspace_dir,
        &home_dir,
        &ssh_priv,
        "SERVICE_TOKEN",
        "after-offboarding",
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

#[cfg(unix)]
#[test]
fn test_user_safe_key_rotation_backup_restore_and_trusted_ci_e2e() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "DEPLOY_TOKEN",
        "deploy-token",
        Some(TEST_MEMBER_HANDLE),
        None,
    );

    rotate_self_key(&workspace_dir, &home_dir, &ssh_priv);
    assert_get_contains(
        &workspace_dir,
        &home_dir,
        &ssh_priv,
        "DEPLOY_TOKEN",
        "deploy-token",
    );

    let restored_home = make_secret_home();
    copy_dir_all(
        &home_dir.path().join("keys"),
        &restored_home.path().join("keys"),
    );
    restrict_restored_keystore(&restored_home.path().join("keys"));
    assert_get_contains(
        &workspace_dir,
        &restored_home,
        &ssh_priv,
        "DEPLOY_TOKEN",
        "deploy-token",
    );

    let encrypted_file = home_dir.path().join("deploy.env.encrypted");
    let decrypted_file = home_dir.path().join("deploy.env");
    let plain_file = home_dir.path().join("deploy.env.plain");
    fs::write(&plain_file, b"DEPLOY_FILE_TOKEN=file-token\n").unwrap();
    encrypt_file_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        &plain_file,
        &encrypted_file,
        TEST_MEMBER_HANDLE,
    );

    let exported_key = export_private_key_to_stdout(&home_dir, &ssh_priv);
    let ci_home = make_secret_home();
    assert_ci_read_commands(
        &workspace_dir,
        &ci_home,
        &exported_key,
        &encrypted_file,
        &decrypted_file,
    );
}

fn add_bob_to_incoming(
    workspace_dir: &TempDir,
    home_dir: &TempDir,
    ssh_priv: &Path,
    bob_public_key: &Path,
) {
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(BOB_MEMBER_HANDLE)
        .arg("-i")
        .arg(ssh_priv)
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success();

    cmd()
        .arg("key")
        .arg("export")
        .arg("--member-handle")
        .arg(BOB_MEMBER_HANDLE)
        .arg("--out")
        .arg(bob_public_key)
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success();

    cmd()
        .arg("member")
        .arg("add")
        .arg(bob_public_key)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();
}

fn approve_rewrap_with_new_member(workspace_dir: &TempDir, home_dir: &TempDir, ssh_priv: &Path) {
    let mut command = rewrap_std_command(workspace_dir.path(), home_dir.path(), ssh_priv);
    let result = run_command_with_pty_script(
        &mut command,
        &[
            ("Accept?", b"y"),
            ("Trust this member set for this secret? [y/N]", b"y\r"),
        ],
    );
    assert!(
        result.status.success(),
        "rewrap should approve new incoming member\n{}",
        result.output
    );
}

fn approve_rewrap_member_set(workspace_dir: &TempDir, home_dir: &TempDir, ssh_priv: &Path) {
    let mut command = rewrap_std_command(workspace_dir.path(), home_dir.path(), ssh_priv);
    assert_member_set_review_success(&mut command);
}

fn approve_member_key(
    workspace_dir: &TempDir,
    home_dir: &TempDir,
    ssh_priv: &Path,
    owner_handle: &str,
    subject_handle: &str,
) {
    let mut command = secretenv_std_cmd();
    command
        .arg("member")
        .arg("verify")
        .arg("--approve")
        .arg("--member-handle")
        .arg(owner_handle)
        .arg(subject_handle)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .env_remove("CI");
    let result = run_command_with_pty(&mut command, "Approve this key?", b"y\r");
    assert!(
        result.status.success(),
        "member verify --approve should approve {subject_handle} for {owner_handle}\n{}",
        result.output
    );
}

fn rotate_self_key(workspace_dir: &TempDir, home_dir: &TempDir, ssh_priv: &Path) {
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("-i")
        .arg(ssh_priv)
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success();

    cmd()
        .arg("join")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    let mut command = rewrap_std_command(workspace_dir.path(), home_dir.path(), ssh_priv);
    assert_member_set_review_success(&mut command);
}

fn export_private_key_to_stdout(home_dir: &TempDir, ssh_priv: &Path) -> String {
    let output = cmd()
        .arg("key")
        .arg("export")
        .arg("--private")
        .arg("--stdout")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin(format!("{CI_KEY_PASSWORD}\n{CI_KEY_PASSWORD}\n"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8(output).unwrap().trim().to_string()
}

fn assert_ci_read_commands(
    workspace_dir: &TempDir,
    ci_home: &TempDir,
    exported_key: &str,
    encrypted_file: &Path,
    decrypted_file: &Path,
) {
    ci_cmd(ci_home, exported_key)
        .arg("get")
        .arg("DEPLOY_TOKEN")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("deploy-token"));

    ci_cmd(ci_home, exported_key)
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("DEPLOY_TOKEN"));

    ci_cmd(ci_home, exported_key)
        .arg("run")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("printf %s \"$DEPLOY_TOKEN\"")
        .assert()
        .success()
        .stdout(predicate::str::contains("deploy-token"));

    ci_cmd(ci_home, exported_key)
        .arg("decrypt")
        .arg(encrypted_file)
        .arg("--out")
        .arg(decrypted_file)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .assert()
        .success();
    assert_eq!(
        fs::read_to_string(decrypted_file).unwrap(),
        "DEPLOY_FILE_TOKEN=file-token\n"
    );

    ci_cmd(ci_home, exported_key)
        .arg("set")
        .arg("UNSUPPORTED")
        .arg("value")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("environment-variable key mode"));
}

fn ci_cmd(home_dir: &TempDir, exported_key: &str) -> assert_cmd::Command {
    let mut command = cmd();
    command
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_PRIVATE_KEY", exported_key)
        .env("SECRETENV_KEY_PASSWORD", CI_KEY_PASSWORD)
        .env("SECRETENV_STRICT_KEY_CHECKING", "no")
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("SECRETENV_SSH_IDENTITY");
    command
}

fn assert_get_contains(
    workspace_dir: &TempDir,
    home_dir: &TempDir,
    ssh_priv: &Path,
    key: &str,
    value: &str,
) {
    assert_get_as_member_contains(
        workspace_dir,
        home_dir,
        ssh_priv,
        TEST_MEMBER_HANDLE,
        key,
        value,
    );
}

fn assert_get_as_member_contains(
    workspace_dir: &TempDir,
    home_dir: &TempDir,
    ssh_priv: &Path,
    member_handle: &str,
    key: &str,
    value: &str,
) {
    cmd()
        .arg("get")
        .arg(key)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(member_handle)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains(value));
}

fn assert_list_contains(workspace_dir: &TempDir, home_dir: &TempDir, ssh_priv: &Path, key: &str) {
    cmd()
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains(key));
}

fn rewrap_std_command(workspace: &Path, home: &Path, ssh_priv: &Path) -> StdCommand {
    let mut command = secretenv_std_cmd();
    command
        .arg("rewrap")
        .arg("--workspace")
        .arg(workspace)
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .env("SECRETENV_HOME", home)
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .env_remove("CI");
    command
}

#[cfg(unix)]
fn restrict_restored_keystore(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    if path.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        for entry in fs::read_dir(path).unwrap() {
            restrict_restored_keystore(&entry.unwrap().path());
        }
        return;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(not(unix))]
fn restrict_restored_keystore(_path: &Path) {}
