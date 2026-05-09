// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::cli::common::{cmd, setup_workspace, TEST_MEMBER_HANDLE};
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_doctor_missing_trust_store_warns_but_exits_success() {
    let (workspace_dir, home_dir, _ssh_temp, _ssh_priv) = setup_workspace();

    cmd()
        .arg("doctor")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--home")
        .arg(home_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .assert()
        .success()
        .stdout(predicate::str::contains("Status: WARN"))
        .stdout(predicate::str::contains(
            "secretenv member verify --approve",
        ));
}

#[test]
fn test_doctor_json_missing_trust_store_warns_but_exits_success() {
    let (workspace_dir, home_dir, _ssh_temp, _ssh_priv) = setup_workspace();

    let output = cmd()
        .arg("doctor")
        .arg("--json")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--home")
        .arg(home_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["status"], "WARN");
    assert_eq!(value["exit_code"], 0);
    assert!(value["summary"]["warn"].as_u64().unwrap() > 0);
    assert!(value["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|check| { check["id"] == "trust_store.present" && check["next_action"].is_string() }));
}

#[test]
fn test_doctor_incomplete_workspace_fails() {
    let workspace = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    fs::create_dir_all(workspace.path().join("members/active")).unwrap();

    cmd()
        .arg("doctor")
        .arg("--workspace")
        .arg(workspace.path())
        .arg("--home")
        .arg(home.path())
        .arg("--member-handle")
        .arg("alice@example.com")
        .arg("--verbose")
        .assert()
        .failure()
        .stdout(predicate::str::contains("Status: FAIL"))
        .stdout(predicate::str::contains("workspace.structure"));
}

#[test]
fn test_doctor_json_incomplete_workspace_fails_with_json() {
    let workspace = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    fs::create_dir_all(workspace.path().join("members/active")).unwrap();

    let output = cmd()
        .arg("doctor")
        .arg("--json")
        .arg("--workspace")
        .arg(workspace.path())
        .arg("--home")
        .arg(home.path())
        .arg("--member-handle")
        .arg("alice@example.com")
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["status"], "FAIL");
    assert_eq!(value["exit_code"], 1);
    assert!(value["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|check| { check["id"] == "workspace.structure" && check["status"] == "FAIL" }));
}
