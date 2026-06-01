// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::setup_init_env;
use crate::cli::common::{cmd, ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE, TEST_MEMBER_HANDLE};
use std::fs;

#[test]
fn test_init_registers_member() {
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

    let member_file = workspace_dir
        .path()
        .join(format!("members/active/{}.json", TEST_MEMBER_HANDLE));
    assert!(member_file.exists());

    let member_json = fs::read_to_string(&member_file).unwrap();
    let public_key: kapsaro_core::cli_api::test_support::domain::public_key::PublicKey =
        serde_json::from_str(&member_json).unwrap();

    assert_eq!(public_key.protected.subject_handle, TEST_MEMBER_HANDLE);
    assert_eq!(
        public_key.protected.format,
        kapsaro_core::cli_api::test_support::domain::wire::format::PUBLIC_KEY_V1
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
        .arg("--member-handle")
        .arg(ALICE_MEMBER_HANDLE)
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(BOB_MEMBER_HANDLE)
        .env("KAPSARO_HOME", home_dir2.path())
        .assert()
        .success();

    assert!(!workspace_dir
        .path()
        .join(format!("members/active/{}.json", BOB_MEMBER_HANDLE))
        .exists());
    assert!(!home_dir2
        .path()
        .join("keys")
        .join(BOB_MEMBER_HANDLE)
        .exists());
}
