// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `join` command
//!
//! Tests the join command that joins an existing workspace without creating it.

use crate::cli::common::{cmd, create_temp_ssh_keypair, TEST_MEMBER_ID};
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn assert_stderr_order(stderr: &[u8], first: &str, second: &str) {
    let stderr = String::from_utf8_lossy(stderr);
    let first_index = stderr
        .find(first)
        .unwrap_or_else(|| panic!("Missing '{first}' in stderr: {stderr}"));
    let second_index = stderr
        .find(second)
        .unwrap_or_else(|| panic!("Missing '{second}' in stderr: {stderr}"));
    assert!(
        first_index < second_index,
        "Expected '{first}' before '{second}' in stderr: {stderr}"
    );
}

// ============================================================================
// join success tests
// ============================================================================

/// Test: join succeeds when workspace exists (pre-created with members/ and secrets/)
#[test]
fn test_join_existing_workspace() {
    let workspace_dir = TempDir::new().unwrap();
    let home_dir = TempDir::new().unwrap();
    let (_ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = create_temp_ssh_keypair();
    let missing_key_message = format!(
        "No local key found for '{}'. Generating a new key...",
        TEST_MEMBER_ID
    );
    let using_ssh_key_message = "Using SSH key:";
    let ssh_determinism_message = "SSH signature determinism: OK";
    let generated_key_message = format!("Generated key for '{}':", TEST_MEMBER_ID);

    // Manually create workspace structure (without init)
    fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir.path().join("members/incoming")).unwrap();
    fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();

    let assert = cmd()
        .arg("join")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains(&missing_key_message))
        .stderr(predicate::str::contains(using_ssh_key_message))
        .stderr(predicate::str::contains(ssh_determinism_message))
        .stderr(predicate::str::contains(&generated_key_message))
        .stderr(predicate::str::contains("Added").and(predicate::str::contains(TEST_MEMBER_ID)));

    assert_stderr_order(
        &assert.get_output().stderr,
        &missing_key_message,
        using_ssh_key_message,
    );
    assert_stderr_order(
        &assert.get_output().stderr,
        using_ssh_key_message,
        ssh_determinism_message,
    );
    assert_stderr_order(
        &assert.get_output().stderr,
        ssh_determinism_message,
        &generated_key_message,
    );

    // Verify member file was created (join registers self to members/incoming/)
    let member_file = workspace_dir
        .path()
        .join("members/incoming")
        .join(format!("{}.json", TEST_MEMBER_ID));
    assert!(
        member_file.exists(),
        "Member file should be created by join"
    );
}

/// Test: join --force overwrites existing member registration
#[test]
fn test_join_force_overwrites_existing_member() {
    let workspace_dir = TempDir::new().unwrap();
    let home_dir = TempDir::new().unwrap();
    let (_ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = create_temp_ssh_keypair();

    // Create workspace structure
    fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir.path().join("members/incoming")).unwrap();
    fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();

    // First join
    cmd()
        .arg("join")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Second join with --force should succeed and show update message
    cmd()
        .arg("join")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .arg("--force")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains("Added").and(predicate::str::contains(TEST_MEMBER_ID)));
}

/// Test: join reuses an existing key without resolving github_user
#[test]
fn test_join_existing_key_ignores_github_user_input() {
    let workspace_dir = TempDir::new().unwrap();
    let home_dir = TempDir::new().unwrap();
    let (_ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = create_temp_ssh_keypair();

    fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir.path().join("members/incoming")).unwrap();
    fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();

    cmd()
        .arg("join")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("join")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .arg("--force")
        .arg("--github-user")
        .arg("definitely-not-a-real-github-user-for-secretenv-tests")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains("Using existing key for"));
}

// ============================================================================
// join failure tests
// ============================================================================

/// Test: join fails when workspace does not exist
#[test]
fn test_join_nonexistent_workspace_fails() {
    let home_dir = TempDir::new().unwrap();
    let (_ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = create_temp_ssh_keypair();

    cmd()
        .arg("join")
        .arg("--workspace")
        .arg("/tmp/secretenv-nonexistent-workspace-xyz-99999")
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

/// Test: join fails when workspace exists but has no members/ or secrets/
#[test]
fn test_join_incomplete_workspace_fails() {
    let workspace_dir = TempDir::new().unwrap();
    let home_dir = TempDir::new().unwrap();
    let (_ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = create_temp_ssh_keypair();

    // workspace_dir exists but has no members/ or secrets/ subdirectories
    cmd()
        .arg("join")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();

    // Verify workspace structure was NOT created
    assert!(
        !workspace_dir.path().join("members").exists(),
        "join should not create members/ directory"
    );
    assert!(
        !workspace_dir.path().join("secrets").exists(),
        "join should not create secrets/ directory"
    );
}

/// Test: init creates workspace, join can then join it
#[test]
fn test_init_then_join_different_member() {
    let workspace_dir = TempDir::new().unwrap();
    let home_dir_alice = TempDir::new().unwrap();
    let home_dir_bob = TempDir::new().unwrap();
    let (_ssh_temp_alice, ssh_priv_alice, _pub_alice, _) = create_temp_ssh_keypair();
    let (_ssh_temp_bob, ssh_priv_bob, _pub_bob, _) = create_temp_ssh_keypair();

    // Alice creates workspace with init
    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg("alice@example.com")
        .env("SECRETENV_HOME", home_dir_alice.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv_alice.to_str().unwrap())
        .assert()
        .success();

    // Bob joins existing workspace with join
    cmd()
        .arg("join")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg("bob@example.com")
        .env("SECRETENV_HOME", home_dir_bob.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv_bob.to_str().unwrap())
        .assert()
        .success();

    // Both member files should exist (alice in active/, bob in incoming/)
    assert!(
        workspace_dir
            .path()
            .join("members/active")
            .join("alice@example.com.json")
            .exists(),
        "alice member file should exist in members/active/"
    );
    assert!(
        workspace_dir
            .path()
            .join("members/incoming")
            .join("bob@example.com.json")
            .exists(),
        "bob member file should exist in members/incoming/ after join"
    );
}
