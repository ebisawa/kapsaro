// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::setup_init_env;
use crate::cli::common::{cmd, ALICE_MEMBER_ID, BOB_MEMBER_ID};

#[test]
fn test_init_with_member_id() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_init_env();

    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    assert!(workspace_dir
        .path()
        .join(format!("members/active/{}.json", ALICE_MEMBER_ID))
        .exists());
}

#[test]
fn test_init_with_env_member_id() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_init_env();

    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_MEMBER_HANDLE", BOB_MEMBER_ID)
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    assert!(workspace_dir
        .path()
        .join(format!("members/active/{}.json", BOB_MEMBER_ID))
        .exists());
}
