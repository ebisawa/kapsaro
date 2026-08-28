// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the permissions of the files CLI commands write out.
//! Pins that decrypted plaintext and an exported private key land owner-only.
//!
//! The module name reads as if it covered output permissions in general, but
//! coverage here is exactly three commands: `decrypt` and `key export
//! --private` write 0600 regardless of the umask, and `encrypt` is pinned to
//! the opposite, following the umask rather than restricting to owner-only.
//! No other command's output mode is exercised in this file.

#![cfg(unix)]
// Setting the umask of the child has no safe wrapper. The call runs after the
// fork and before the exec, so it changes nothing in the test process itself
// and cannot affect the tests running beside it.
#![allow(unsafe_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;

use assert_cmd::Command;

use crate::cli::common::{
    assert_member_set_review_success, encrypt_file_with_member_set_review,
    generate_temp_ssh_keypair, kapsaro_std_cmd, make_secret_home, setup_workspace,
    TEST_MEMBER_HANDLE,
};

/// The umask a machine is normally set up with.
///
/// The point of these tests is that the mode does not follow it. Pinning the
/// value here rather than inheriting the developer's own umask is what keeps
/// the assertion from passing on a machine whose umask already masks the group
/// and other bits.
const ORDINARY_UMASK: libc::mode_t = 0o022;

/// A kapsaro command that runs under an ordinary umask whatever this test
/// process carries.
fn std_cmd_under_ordinary_umask() -> std::process::Command {
    let mut command = kapsaro_std_cmd();
    unsafe {
        command.pre_exec(|| {
            libc::umask(ORDINARY_UMASK);
            Ok(())
        });
    }
    command
}

fn cmd_under_ordinary_umask() -> Command {
    Command::from_std(std_cmd_under_ordinary_umask())
}

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// Decrypted plaintext is the secret the whole document existed to protect, so
/// the file it lands in is readable by its owner alone whatever the umask says.
#[test]
fn test_decrypt_writes_plaintext_readable_only_by_its_owner() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let input_file = home_dir.path().join("secret.env");
    fs::write(&input_file, b"SECRET_VALUE=hello\n").unwrap();
    let encrypted_file = home_dir.path().join("secret.env.encrypted");
    let decrypted_file = home_dir.path().join("plain.env");

    encrypt_file_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        &input_file,
        &encrypted_file,
        TEST_MEMBER_HANDLE,
    );

    cmd_under_ordinary_umask()
        .arg("decrypt")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--out")
        .arg(decrypted_file.to_str().unwrap())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    assert_eq!(mode_of(&decrypted_file), 0o600);
    assert_eq!(
        fs::read_to_string(&decrypted_file).unwrap(),
        "SECRET_VALUE=hello\n"
    );
}

/// An exported private key is protected by a password, but the file still holds
/// the only copy an attacker needs to start guessing at it offline.
#[test]
fn test_key_export_private_writes_a_key_file_readable_only_by_its_owner() {
    let temp_dir = make_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    let export_file = temp_dir.path().join("portable-private-key.txt");

    cmd_under_ordinary_umask()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    cmd_under_ordinary_umask()
        .arg("key")
        .arg("export")
        .arg("--private")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--out")
        .arg(export_file.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .write_stdin("strong-password-42-xx\nstrong-password-42-xx\n")
        .assert()
        .success();

    assert_eq!(mode_of(&export_file), 0o600);

    drop(ssh_temp);
}

/// An encrypted artifact is shared through git, so it keeps the mode the
/// checkout expects rather than one only its author can read.
///
/// The child runs under a pinned ordinary umask and the expected mode is spelled
/// out, so a machine whose own umask already masks the group and other bits
/// cannot make the assertion agree with an implementation that saves the
/// artifact owner-only.
#[test]
fn test_encrypt_writes_an_artifact_with_the_mode_the_umask_allows() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let input_file = home_dir.path().join("shared.env");
    fs::write(&input_file, b"SHARED=value\n").unwrap();
    let encrypted_file = home_dir.path().join("shared.env.encrypted");

    let mut command = std_cmd_under_ordinary_umask();
    command
        .arg("encrypt")
        .arg(&input_file)
        .arg("--out")
        .arg(&encrypted_file)
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", &ssh_priv);
    assert_member_set_review_success(&mut command);

    assert_eq!(mode_of(&encrypted_file), 0o644);
}
