// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::setup_init_env;
use crate::cli::common::{cmd, TEST_MEMBER_HANDLE};

#[test]
fn test_init_creates_workspace() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_init_env();

    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    assert!(workspace_dir.path().join("members").exists());
    assert!(workspace_dir.path().join("secrets").exists());
    assert!(workspace_dir.path().join("members/active").exists());
    assert!(workspace_dir.path().join("members/incoming").exists());
    assert!(workspace_dir
        .path()
        .join("members/active/.gitkeep")
        .exists());
    assert!(workspace_dir
        .path()
        .join("members/incoming/.gitkeep")
        .exists());
    assert!(workspace_dir.path().join("secrets/.gitkeep").exists());
}

#[test]
fn test_init_completes_incomplete_workspace_structure() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_init_env();

    std::fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();

    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    assert!(workspace_dir
        .path()
        .join("members/incoming/.gitkeep")
        .exists());
    assert!(workspace_dir.path().join("secrets/.gitkeep").exists());
    assert!(workspace_dir
        .path()
        .join(format!("members/active/{}.json", TEST_MEMBER_HANDLE))
        .exists());
}
