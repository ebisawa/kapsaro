// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::setup_init_env;
use crate::cli::common::{cmd, ALICE_MEMBER_ID, BOB_MEMBER_ID, TEST_MEMBER_ID};
use predicates::prelude::*;

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

#[test]
fn test_init_new_workspace_new_key_output() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_init_env();
    let missing_key_message = format!(
        "No local key found for '{}'. Generating a new key...",
        TEST_MEMBER_ID
    );
    let using_ssh_key_message = "Using SSH key:";
    let ssh_determinism_message = "SSH signature determinism: OK";
    let generated_key_message = format!("Generated key for '{}':", TEST_MEMBER_ID);

    let assert = cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains("Creating workspace"))
        .stderr(predicate::str::contains(&missing_key_message))
        .stderr(predicate::str::contains(using_ssh_key_message))
        .stderr(predicate::str::contains(ssh_determinism_message))
        .stderr(predicate::str::contains(&generated_key_message))
        .stderr(predicate::str::contains("Key ID:"))
        .stderr(predicate::str::contains("Expires:"))
        .stderr(predicate::str::contains(format!(
            "Added '{}' to members/active/",
            TEST_MEMBER_ID
        )))
        .stderr(predicate::str::contains(
            "Ready! Commit .secretenv/ to your repository.",
        ));

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
}

#[test]
fn test_init_existing_workspace_new_key_output() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_init_env();
    let home_dir2 = tempfile::TempDir::new().unwrap();

    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    let missing_key_message = format!(
        "No local key found for '{}'. Generating a new key...",
        BOB_MEMBER_ID
    );
    let using_ssh_key_message = "Using SSH key:";
    let ssh_determinism_message = "SSH signature determinism: OK";
    let generated_key_message = format!("Generated key for '{}':", BOB_MEMBER_ID);

    let assert = cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(BOB_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir2.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains(&missing_key_message))
        .stderr(predicate::str::contains(using_ssh_key_message))
        .stderr(predicate::str::contains(ssh_determinism_message))
        .stderr(predicate::str::contains(&generated_key_message))
        .stderr(predicate::str::contains(format!(
            "Added '{}' to members/active/",
            BOB_MEMBER_ID
        )))
        .stderr(predicate::str::contains(
            "Ready! Create a PR to share your public key with the team.",
        ));

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
}

#[test]
fn test_init_existing_workspace_existing_key_output() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_init_env();

    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .arg("--force")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains(format!(
            "Using existing key for '{}'",
            TEST_MEMBER_ID
        )))
        .stderr(predicate::str::contains(format!(
            "Added '{}' to members/active/",
            TEST_MEMBER_ID
        )));
}

#[test]
fn test_init_already_member_ci_output() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_init_env();

    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .env("CI", "true")
        .assert()
        .success()
        .stderr(predicate::str::contains(format!(
            "Member '{}' already exists in workspace",
            TEST_MEMBER_ID
        )));
}
