// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::setup_init_env;
use crate::cli::common::{cmd, TEST_MEMBER_ID};
use std::fs;

#[test]
fn test_init_registers_member() {
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

    let member_file = workspace_dir
        .path()
        .join(format!("members/active/{}.json", TEST_MEMBER_ID));
    assert!(member_file.exists());

    let member_json = fs::read_to_string(&member_file).unwrap();
    let public_key: secretenv::model::public_key::PublicKey =
        serde_json::from_str(&member_json).unwrap();

    assert_eq!(public_key.protected.member_id, TEST_MEMBER_ID);
    assert_eq!(
        public_key.protected.format,
        secretenv::model::identifiers::format::PUBLIC_KEY_V4
    );
}

#[test]
fn test_init_force_overwrite_member() {
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

    let member_file = workspace_dir
        .path()
        .join(format!("members/active/{}.json", TEST_MEMBER_ID));
    fs::write(&member_file, "modified content").unwrap();

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
        .success();

    let new_content = fs::read_to_string(&member_file).unwrap();
    assert_ne!(new_content, "modified content");
    let _: secretenv::model::public_key::PublicKey = serde_json::from_str(&new_content).unwrap();
}

#[test]
fn test_init_existing_key_ignores_github_user_input() {
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
        .arg("--github-user")
        .arg("definitely-not-a-real-github-user-for-secretenv-tests")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();
}
