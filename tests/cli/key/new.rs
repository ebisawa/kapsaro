// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `key new` command

use crate::cli::common::{cmd, generate_temp_ssh_keypair, setup_secret_home, TEST_MEMBER_HANDLE};
#[cfg(unix)]
use crate::cli::common::{kapsaro_std_cmd, run_command_with_pty_script};
use crate::cli::key::find_kid_in_member_dir;
use kapsaro_core::test_support::domain::private_key::PrivateKey;
use kapsaro_core::test_support::domain::wire::format;
use predicates::prelude::*;
use std::fs;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::symlink;

fn build_auto_key_new_command(
    local_home: &Path,
    process_home: &Path,
    ssh_identity: &Path,
) -> assert_cmd::Command {
    let mut command = cmd();
    command
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("-i")
        .arg(ssh_identity)
        .env("KAPSARO_HOME", local_home)
        .env("HOME", process_home)
        .env_remove("KAPSARO_SSH_SIGNING_METHOD")
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("KAPSARO_GITHUB_USER");
    command
}

/// Pointing the local state root at another volume through a symlink is a
/// supported setup, so the keystore is created behind the link.
#[cfg(unix)]
#[test]
fn test_key_new_writes_through_an_explicit_home_symlink() {
    let temp_dir = setup_secret_home();
    let outside = temp_dir.path().join("outside");
    let home = temp_dir.path().join("home");
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    fs::create_dir(&outside).unwrap();
    symlink(&outside, &home).unwrap();

    cmd()
        .arg("key")
        .arg("new")
        .arg("--home")
        .arg(&home)
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("-i")
        .arg(&ssh_priv)
        .env_remove("KAPSARO_GITHUB_USER")
        .assert()
        .success();

    assert!(outside.join("keys").join(TEST_MEMBER_HANDLE).is_dir());
    drop(ssh_temp);
}

#[cfg(unix)]
#[test]
fn test_key_new_writes_through_an_environment_home_symlink() {
    let temp_dir = setup_secret_home();
    let outside = temp_dir.path().join("outside");
    let home = temp_dir.path().join("home");
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    fs::create_dir(&outside).unwrap();
    symlink(&outside, &home).unwrap();

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("-i")
        .arg(&ssh_priv)
        .env("KAPSARO_HOME", &home)
        .env_remove("KAPSARO_GITHUB_USER")
        .assert()
        .success();

    assert!(outside.join("keys").join(TEST_MEMBER_HANDLE).is_dir());
    drop(ssh_temp);
}

#[test]
fn test_key_new_requires_member_handle_before_ssh_resolution() {
    let temp_dir = setup_secret_home();

    cmd()
        .arg("key")
        .arg("new")
        .arg("--valid-for")
        .arg("1d")
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("member handle not configured")
                .and(predicate::str::contains(
                    "Run in an interactive terminal for prompt",
                ))
                .and(predicate::str::contains("SSH key").not())
                .and(predicate::str::contains("GitHub username").not()),
        );
}

#[test]
fn test_key_new_invalid_github_user_before_ssh_resolution_fails() {
    let home = setup_secret_home();
    let missing_identity = home.path().join("missing-identity");
    let member_dir = home.path().join("keys").join(TEST_MEMBER_HANDLE);

    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--github-user")
        .arg("alice/keys")
        .arg("--ssh-identity")
        .arg(&missing_identity)
        .env("KAPSARO_HOME", home.path())
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("GitHub login")
                .and(predicate::str::contains("SSH identity").not()),
        );

    assert!(
        !member_dir.exists(),
        "invalid login must not generate a key"
    );
    assert!(
        !member_dir.join("active").exists(),
        "invalid login must not activate a key"
    );
}

#[test]
fn test_key_new_auto_selects_identity_agent() {
    let local_home = setup_secret_home();
    let process_home = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    let socket_path = process_home.path().join("missing-identity-agent.sock");
    let ssh_dir = process_home.path().join(".ssh");
    fs::create_dir(&ssh_dir).unwrap();
    fs::write(
        ssh_dir.join("config"),
        format!("Host *\n    IdentityAgent \"{}\"\n", socket_path.display()),
    )
    .unwrap();

    build_auto_key_new_command(local_home.path(), process_home.path(), &ssh_priv)
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("ssh-agent connect failed for")
                .and(predicate::str::contains("missing-identity-agent.sock")),
        );

    drop(ssh_temp);
}

#[test]
fn test_key_new_auto_selects_ssh_auth_sock() {
    let local_home = setup_secret_home();
    let process_home = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    let socket_path = process_home.path().join("missing-environment-agent.sock");

    build_auto_key_new_command(local_home.path(), process_home.path(), &ssh_priv)
        .env("SSH_AUTH_SOCK", &socket_path)
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("ssh-agent connect failed for")
                .and(predicate::str::contains("missing-environment-agent.sock")),
        );

    drop(ssh_temp);
}

#[test]
fn test_key_new_auto_selects_ssh_keygen_without_agent() {
    let local_home = setup_secret_home();
    let process_home = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    build_auto_key_new_command(local_home.path(), process_home.path(), &ssh_priv)
        .assert()
        .success();

    assert!(
        local_home
            .path()
            .join("keys")
            .join(TEST_MEMBER_HANDLE)
            .is_dir(),
        "keygen selection must publish the generated Kapsaro key"
    );
    drop(ssh_temp);
}

#[cfg(unix)]
#[test]
fn test_key_new_prompts_for_member_handle_when_unconfigured() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let mut command = kapsaro_std_cmd();
    command
        .arg("key")
        .arg("new")
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("KAPSARO_HOME", temp_dir.path())
        .env_remove("KAPSARO_GITHUB_USER")
        .env_remove("KAPSARO_MEMBER_HANDLE");

    let member_handle_input = format!("{TEST_MEMBER_HANDLE}\r");
    let result = run_command_with_pty_script(
        &mut command,
        &[
            ("Enter your member handle", member_handle_input.as_bytes()),
            ("Enter your GitHub username", b"\r"),
        ],
    );

    assert!(
        result.status.success(),
        "key new should succeed after member handle prompt:\n{}",
        result.output
    );

    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(TEST_MEMBER_HANDLE);
    assert!(
        member_dir.exists(),
        "Member directory should be created: {}",
        member_dir.display()
    );

    let kid = find_kid_in_member_dir(&member_dir);
    let private_key_path = member_dir.join(&kid).join("private.json");
    let private_json = fs::read_to_string(&private_key_path).unwrap();
    let private_key: PrivateKey =
        serde_json::from_str(&private_json).expect("Should parse as PrivateKey");

    assert_eq!(private_key.protected.subject_handle, TEST_MEMBER_HANDLE);

    drop(ssh_temp);
}

#[test]
fn test_key_new_generates_private_key() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Run key new command
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

    // Get keystore root
    let keystore_root = temp_dir.path().join("keys");

    // Find the generated kid directory
    let member_dir = keystore_root.join(member_handle);
    assert!(
        member_dir.exists(),
        "Member directory should be created: {}",
        member_dir.display()
    );

    // Find the generated kid
    let kid = find_kid_in_member_dir(&member_dir);

    // Verify private.json exists
    let private_key_path = member_dir.join(&kid).join("private.json");
    assert!(
        private_key_path.exists(),
        "private.json should exist at: {}",
        private_key_path.display()
    );

    // Parse private.json as PrivateKey
    let private_json = fs::read_to_string(&private_key_path).unwrap();
    let private_key: PrivateKey =
        serde_json::from_str(&private_json).expect("Should parse as PrivateKey");

    // Verify fields
    assert_eq!(
        private_key.protected.format,
        format::PRIVATE_KEY_V1,
        "Format should be kapsaro:format:private-key@1"
    );
    assert_eq!(
        private_key.protected.subject_handle, member_handle,
        "member_handle should match"
    );
    assert_eq!(
        private_key.protected.kid, kid,
        "kid should match directory name"
    );
    assert!(
        !private_key.protected.created_at.is_empty(),
        "created_at should be set"
    );
    assert!(
        !private_key.protected.expires_at.is_empty(),
        "expires_at should be set"
    );

    // Keep temp directories alive until test ends
    drop(ssh_temp);
}

#[test]
fn test_key_new_expires_at_option() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;
    let expires_at = "2027-12-31T23:59:59Z";

    // Run key new command with --expires-at
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .arg("--expires-at")
        .arg(expires_at)
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    // Read private.json
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);

    let private_key_path = member_dir.join(&kid).join("private.json");
    let private_json = fs::read_to_string(&private_key_path).unwrap();
    let private_key: PrivateKey = serde_json::from_str(&private_json).unwrap();

    // Verify expires_at
    assert_eq!(
        private_key.protected.expires_at, expires_at,
        "expires_at should match the specified date"
    );

    // Verify it can be parsed as RFC3339
    time::OffsetDateTime::parse(
        &private_key.protected.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .expect("expires_at should be valid RFC3339");

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_new_valid_for_1y() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Run key new command with --valid-for 1y
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .arg("--valid-for")
        .arg("1y")
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    // Read private.json
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);

    let private_key_path = member_dir.join(&kid).join("private.json");
    let private_json = fs::read_to_string(&private_key_path).unwrap();
    let private_key: PrivateKey = serde_json::from_str(&private_json).unwrap();

    // Parse expires_at
    let expires_at = time::OffsetDateTime::parse(
        &private_key.protected.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .expect("expires_at should be valid RFC3339");

    let now = time::OffsetDateTime::now_utc();
    let one_year_later = now + time::Duration::days(365);

    // Verify expires_at is approximately 1 year from now (within 1 minute tolerance)
    let diff = (expires_at - one_year_later).abs();
    assert!(
        diff < time::Duration::minutes(1),
        "expires_at should be approximately 1 year from now"
    );

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_new_valid_for_6m() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Run key new command with --valid-for 6m
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .arg("--valid-for")
        .arg("6m")
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    // Read private.json
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);

    let private_key_path = member_dir.join(&kid).join("private.json");
    let private_json = fs::read_to_string(&private_key_path).unwrap();
    let private_key: PrivateKey = serde_json::from_str(&private_json).unwrap();

    // Parse expires_at
    let expires_at = time::OffsetDateTime::parse(
        &private_key.protected.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .expect("expires_at should be valid RFC3339");

    let now = time::OffsetDateTime::now_utc();
    let six_months_later = now + time::Duration::days(6 * 30);

    // Verify expires_at is approximately 6 months from now (within 1 minute tolerance)
    let diff = (expires_at - six_months_later).abs();
    assert!(
        diff < time::Duration::minutes(1),
        "expires_at should be approximately 6 months from now"
    );

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_new_valid_for_30d() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Run key new command with --valid-for 30d
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .arg("--valid-for")
        .arg("30d")
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    // Read private.json
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);

    let private_key_path = member_dir.join(&kid).join("private.json");
    let private_json = fs::read_to_string(&private_key_path).unwrap();
    let private_key: PrivateKey = serde_json::from_str(&private_json).unwrap();

    // Parse expires_at
    let expires_at = time::OffsetDateTime::parse(
        &private_key.protected.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .expect("expires_at should be valid RFC3339");

    let now = time::OffsetDateTime::now_utc();
    let thirty_days_later = now + time::Duration::days(30);

    // Verify expires_at is approximately 30 days from now (within 1 minute tolerance)
    let diff = (expires_at - thirty_days_later).abs();
    assert!(
        diff < time::Duration::minutes(1),
        "expires_at should be approximately 30 days from now"
    );

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_new_no_activate_option() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Run key new command with --no-activate
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .arg("--no-activate")
        .env("KAPSARO_HOME", temp_dir.path())
        .assert()
        .success();

    // Verify key was created
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);

    let private_key_path = member_dir.join(&kid).join("private.json");
    assert!(private_key_path.exists(), "private.json should be created");

    // Verify active file is NOT created
    let active_path = member_dir.join("active");
    assert!(
        !active_path.exists(),
        "active file should NOT be created with --no-activate"
    );

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_new_default_activate() {
    let temp_dir = setup_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    let member_handle = TEST_MEMBER_HANDLE;

    // Run key new command without --no-activate
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

    // Get the generated kid
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_handle);
    let kid = find_kid_in_member_dir(&member_dir);

    // Verify active file is created
    use kapsaro_core::test_support::storage::keystore::active::load_active_kid;
    let active_kid = load_active_kid(member_handle, &keystore_root).expect("Should get active kid");
    assert_eq!(
        active_kid,
        Some(kid),
        "Active kid should match the generated kid"
    );

    // Keep temp directories alive
    drop(ssh_temp);
}
