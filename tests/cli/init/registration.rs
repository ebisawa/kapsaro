// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::setup_init_env;
use crate::cli::common::{cmd, ALICE_MEMBER_ID, BOB_MEMBER_ID, TEST_MEMBER_ID};
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
fn test_init_existing_workspace_does_not_register_new_member() {
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

    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(BOB_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir2.path())
        .assert()
        .success();

    assert!(!workspace_dir
        .path()
        .join(format!("members/active/{}.json", BOB_MEMBER_ID))
        .exists());
    assert!(!home_dir2.path().join("keys").join(BOB_MEMBER_ID).exists());
}

#[test]
fn test_init_existing_workspace_succeeds_without_member_id() {
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
        .env("SECRETENV_HOME", home_dir.path())
        .env("CI", "true")
        .assert()
        .success()
        .stderr(predicates::str::contains("Workspace already initialized"));
}

#[test]
fn test_init_rejects_force_option() {
    let (workspace_dir, _home_dir, _ssh_temp, _ssh_priv) = setup_init_env();

    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--force")
        .assert()
        .failure()
        .stderr(predicates::str::contains("--force"));
}
