// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::setup_init_env;
use crate::cli::common::{
    assert_stderr_order, cmd, ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE, TEST_MEMBER_HANDLE,
};
use predicates::prelude::*;

#[test]
fn test_init_new_workspace_new_key_output() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_init_env();
    let missing_key_message = format!(
        "No local key found for '{}'. Generating a new key...",
        TEST_MEMBER_HANDLE
    );
    let using_ssh_key_message = "Using SSH key:";
    let ssh_determinism_message = "SSH signature determinism: OK";
    let generated_key_message = format!("Generated key for '{}':", TEST_MEMBER_HANDLE);

    let assert = cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
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
            TEST_MEMBER_HANDLE
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
fn test_init_existing_workspace_noop_output() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_init_env();
    let home_dir2 = tempfile::TempDir::new().unwrap();

    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(BOB_MEMBER_HANDLE)
        .env("SECRETENV_HOME", home_dir2.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("Workspace already initialized"))
        .stderr(predicate::str::contains(
            "`secretenv init` only bootstraps a new workspace",
        ))
        .stderr(predicate::str::contains("Use `secretenv join`"))
        .stderr(predicate::str::contains("Added").not())
        .stderr(predicate::str::contains("Using SSH key:").not());
}

#[test]
fn test_init_already_member_ci_output() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_init_env();

    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("CI", "true")
        .assert()
        .success()
        .stderr(predicate::str::contains("Workspace already initialized"))
        .stderr(predicate::str::contains("Use `secretenv join`"));
}
