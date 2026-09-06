// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `key export` command

use crate::cli::common::{
    cmd, generate_temp_ssh_keypair, setup_secret_home, ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE,
    TEST_MEMBER_HANDLE,
};
use crate::cli::key::{find_kid_in_member_dir, install_secondary_member_fixture};
use console::strip_ansi_codes;
use kapsaro_core::test_support::helpers::kid::format_kid_display;
use kapsaro_test_support::fixture::setup_test_keystore_from_fixtures;
use predicates::prelude::*;
use tempfile::TempDir;

fn generate_exportable_private_key(
    temp_dir: &TempDir,
    ssh_priv: &std::path::Path,
    member_handle: &str,
) {
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();
}

#[test]
fn test_key_export_explicit_kid() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Generate a key
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    // Get the kid
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);

    // Export to a temp file
    let export_file = temp_dir.path().join("exported.json");

    cmd()
        .arg("key")
        .arg("export")
        .arg(&kid)
        .arg("--member-handle")
        .arg(member_handle)
        .arg("--out")
        .arg(export_file.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    // Verify exported file exists and is valid JSON
    assert!(export_file.exists(), "Exported file should exist");

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_export_active() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Generate a key
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    // Export active key to a temp file
    let export_file = temp_dir.path().join("exported.json");

    cmd()
        .arg("key")
        .arg("export")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("--out")
        .arg(export_file.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    // Verify exported file exists and is valid
    assert!(export_file.exists(), "Exported file should exist");

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_export_public_with_config_member_handle_in_multi_member_home() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    install_secondary_member_fixture(&home, BOB_MEMBER_HANDLE);
    std::fs::write(
        home.path().join("config.toml"),
        format!("member_handle = \"{ALICE_MEMBER_HANDLE}\"\n"),
    )
    .unwrap();
    let export_file = home.path().join("configured-member-public.json");

    cmd()
        .arg("key")
        .arg("export")
        .arg("--out")
        .arg(&export_file)
        .arg("--home")
        .arg(home.path())
        .env_remove("KAPSARO_MEMBER_HANDLE")
        .assert()
        .success();

    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(export_file).unwrap()).unwrap();
    assert_eq!(document["protected"]["subject_handle"], ALICE_MEMBER_HANDLE);
}

#[test]
fn test_key_export_accepts_display_kid() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    let member_handle = TEST_MEMBER_HANDLE;

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);
    let export_file = temp_dir.path().join("display-exported.json");

    cmd()
        .arg("key")
        .arg("export")
        .arg(format_kid_display(&kid).unwrap())
        .arg("--member-handle")
        .arg(member_handle)
        .arg("--out")
        .arg(export_file.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    assert!(export_file.exists(), "Exported file should exist");

    drop(ssh_temp);
}

#[test]
fn test_key_export_private_rejects_short_password_by_default() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    let member_handle = TEST_MEMBER_HANDLE;
    generate_exportable_private_key(&temp_dir, &ssh_priv, member_handle);
    let export_file = temp_dir.path().join("portable-private-key.txt");

    cmd()
        .arg("key")
        .arg("export")
        .arg("--private")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("--out")
        .arg(export_file.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin("12345678\n12345678\n")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("at least 20 bytes")
                .and(predicate::str::contains("Warning:").not()),
        );

    assert!(!export_file.exists(), "export file should not be written");
    drop(ssh_temp);
}

#[test]
fn test_key_export_private_colors_short_password_error_when_forced() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    let member_handle = TEST_MEMBER_HANDLE;
    generate_exportable_private_key(&temp_dir, &ssh_priv, member_handle);
    let export_file = temp_dir.path().join("portable-private-key.txt");

    let assert = cmd()
        .arg("key")
        .arg("export")
        .arg("--private")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("--out")
        .arg(export_file.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .env("CLICOLOR_FORCE", "1")
        .write_stdin("12345678\n12345678\n")
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("\u{1b}[31mError: Password must be at least 20 bytes"),
        "expected ANSI-colored error in stderr, got: {stderr}"
    );
    assert!(
        strip_ansi_codes(&stderr).contains("Error: Password must be at least 20 bytes"),
        "expected error text after stripping ANSI, got: {stderr}"
    );

    assert!(!export_file.exists(), "export file should not be written");
    drop(ssh_temp);
}

#[test]
fn test_key_export_private_warns_for_allowed_weak_password_to_file() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    let member_handle = TEST_MEMBER_HANDLE;
    generate_exportable_private_key(&temp_dir, &ssh_priv, member_handle);
    let export_file = temp_dir.path().join("portable-private-key.txt");

    cmd()
        .arg("key")
        .arg("export")
        .arg("--private")
        .arg("--allow-weak-password")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("--out")
        .arg(export_file.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin("12345678\n12345678\n")
        .assert()
        .success()
        .stderr(
            predicate::str::contains("Warning:")
                .and(predicate::str::contains("Recommended: at least 20 bytes")),
        );

    assert!(export_file.exists(), "export should still succeed");
    drop(ssh_temp);
}

#[test]
fn test_key_export_private_colors_short_password_warning_when_forced() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    let member_handle = TEST_MEMBER_HANDLE;
    generate_exportable_private_key(&temp_dir, &ssh_priv, member_handle);
    let export_file = temp_dir.path().join("portable-private-key.txt");

    let assert = cmd()
        .arg("key")
        .arg("export")
        .arg("--private")
        .arg("--allow-weak-password")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("--out")
        .arg(export_file.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .env("CLICOLOR_FORCE", "1")
        .write_stdin("12345678\n12345678\n")
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("\u{1b}[33mWarning: Password accepted"),
        "expected ANSI-colored warning in stderr, got: {stderr}"
    );
    assert!(
        strip_ansi_codes(&stderr).contains("Warning: Password accepted"),
        "expected warning text after stripping ANSI, got: {stderr}"
    );

    drop(ssh_temp);
}

#[test]
fn test_key_export_private_warns_for_accepted_short_password_only_on_stderr() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    let member_handle = TEST_MEMBER_HANDLE;
    generate_exportable_private_key(&temp_dir, &ssh_priv, member_handle);

    let output = cmd()
        .arg("key")
        .arg("export")
        .arg("--private")
        .arg("--allow-weak-password")
        .arg("--stdout")
        .arg("--member-handle")
        .arg(member_handle)
        .env("KAPSARO_HOME", temp_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin("12345678\n12345678\n")
        .assert()
        .success()
        .get_output()
        .clone();

    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");
    let exported = stdout.trim();
    assert!(!exported.is_empty(), "stdout should contain exported key");
    assert!(
        exported
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
        "stdout should contain only base64url text: {stdout:?}"
    );
    assert!(
        stderr.contains("Warning:") && stderr.contains("Recommended: at least 20 bytes"),
        "stderr should contain password strength warning: {stderr}"
    );
    assert!(
        !stdout.contains("Warning:"),
        "stdout must not contain warnings: {stdout}"
    );

    drop(ssh_temp);
}

#[test]
fn test_key_export_private_does_not_warn_for_recommended_password() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    let member_handle = TEST_MEMBER_HANDLE;
    generate_exportable_private_key(&temp_dir, &ssh_priv, member_handle);
    let export_file = temp_dir.path().join("portable-private-key.txt");

    cmd()
        .arg("key")
        .arg("export")
        .arg("--private")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("--out")
        .arg(export_file.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin("strong-password-42-xx\nstrong-password-42-xx\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("recommended 20 bytes").not());

    assert!(export_file.exists(), "export file should be written");

    drop(ssh_temp);
}

#[test]
fn test_key_export_private_writes_base64url_to_stdout_with_stdout_flag() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    let member_handle = TEST_MEMBER_HANDLE;

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    let output = cmd()
        .arg("key")
        .arg("export")
        .arg("--private")
        .arg("--stdout")
        .arg("--member-handle")
        .arg(member_handle)
        .env("KAPSARO_HOME", temp_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin("strong-password-42-xx\nstrong-password-42-xx\n")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8(output).expect("stdout should be UTF-8");
    let exported = stdout.trim();
    assert!(!exported.is_empty(), "stdout should contain exported key");
    assert!(
        exported
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
        "stdout should contain only base64url text: {stdout:?}"
    );

    drop(ssh_temp);
}

#[test]
fn test_key_export_private_requires_member_handle_before_password_input() {
    let temp_dir = setup_secret_home();

    cmd()
        .arg("key")
        .arg("export")
        .arg("--private")
        .arg("--stdout")
        .env("KAPSARO_HOME", temp_dir.path())
        .write_stdin("strong-password-42\n")
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("member handle not configured")
                .and(predicate::str::contains("Passwords do not match").not()),
        );
}

#[test]
fn test_key_export_private_requires_explicit_output_destination() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    let member_handle = TEST_MEMBER_HANDLE;

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    cmd()
        .arg("key")
        .arg("export")
        .arg("--private")
        .arg("--member-handle")
        .arg(member_handle)
        .env("KAPSARO_HOME", temp_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stdout(predicates::prelude::predicate::str::is_empty())
        .stderr(predicates::prelude::predicate::str::contains(
            "requires either --out or --stdout",
        ));

    drop(ssh_temp);
}

#[test]
fn test_key_export_private_rejects_stdout_and_out_together() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    let member_handle = TEST_MEMBER_HANDLE;

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    let export_file = temp_dir.path().join("portable-private-key.txt");

    cmd()
        .arg("key")
        .arg("export")
        .arg("--private")
        .arg("--stdout")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("--out")
        .arg(export_file.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicates::prelude::predicate::str::contains(
            "cannot be used with",
        ));

    drop(ssh_temp);
}

/// A private key file group or other can read is not exported at all.
///
/// Every other local state entry is reported as a warning and the command goes
/// on, because the mode of a file on a shared host is the operator's decision.
/// The private half is where that decision cannot be deferred: once the key is
/// exported, whoever else could read the file holds it too.
#[cfg(unix)]
#[test]
fn test_key_export_private_refuses_a_private_key_others_can_read() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    let member_handle = TEST_MEMBER_HANDLE;
    generate_exportable_private_key(&temp_dir, &ssh_priv, member_handle);

    let member_dir = temp_dir.path().join("keys").join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);
    let private_path = member_dir.join(&kid).join("private.json");
    fs::set_permissions(&private_path, fs::Permissions::from_mode(0o644)).unwrap();

    cmd()
        .arg("key")
        .arg("export")
        .arg("--private")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("--out")
        .arg(temp_dir.path().join("portable-private-key.txt"))
        .env("KAPSARO_HOME", temp_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin("strong-password-42-xx\nstrong-password-42-xx\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Insecure permissions 0644"))
        .stderr(predicate::str::contains("chmod 0600"));

    drop(ssh_temp);
}

/// The public half carries no secret, so a mode others can read is named and
/// the command still produces what the operator asked for.
#[cfg(unix)]
#[test]
fn test_key_export_private_warns_about_a_public_key_others_can_read() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    let member_handle = TEST_MEMBER_HANDLE;
    generate_exportable_private_key(&temp_dir, &ssh_priv, member_handle);

    let member_dir = temp_dir.path().join("keys").join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);
    let public_path = member_dir.join(&kid).join("public.json");
    fs::set_permissions(&public_path, fs::Permissions::from_mode(0o644)).unwrap();
    let export_file = temp_dir.path().join("portable-private-key.txt");

    cmd()
        .arg("key")
        .arg("export")
        .arg("--private")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("--out")
        .arg(export_file.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin("strong-password-42-xx\nstrong-password-42-xx\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("Insecure permissions 0644"));

    assert!(export_file.exists());

    drop(ssh_temp);
}
