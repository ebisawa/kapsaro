// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::doctor::types::DoctorStatus;
use crate::app::doctor::{execute_doctor_command, DoctorRequest};
use crate::test_utils::EnvGuard;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_doctor_reports_missing_workspace_structure_as_fail() {
    let workspace = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();

    let report = execute_doctor_command(DoctorRequest {
        workspace: Some(workspace.path().to_path_buf()),
        home: Some(home.path().to_path_buf()),
        member_handle: Some("alice@example.com".to_string()),
        debug: false,
        verbose: false,
    })
    .unwrap();

    assert!(report
        .checks()
        .iter()
        .any(|check| check.id == "workspace.structure" && check.status == DoctorStatus::Fail));
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn test_doctor_reports_empty_incoming_as_ok() {
    let workspace = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace.path().join("members/incoming")).unwrap();
    std::fs::create_dir_all(workspace.path().join("secrets")).unwrap();

    let report = execute_doctor_command(DoctorRequest {
        workspace: Some(workspace.path().to_path_buf()),
        home: Some(home.path().to_path_buf()),
        member_handle: Some("alice@example.com".to_string()),
        debug: false,
        verbose: false,
    })
    .unwrap();

    assert!(report
        .checks()
        .iter()
        .any(|check| check.id == "members.incoming.empty" && check.status == DoctorStatus::Ok));
}

#[test]
fn test_doctor_reports_env_workspace_structure_failure() {
    let _guard = EnvGuard::new(&["KAPSARO_WORKSPACE"]);
    let workspace = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    fs::create_dir_all(workspace.path().join("members/active")).unwrap();
    std::env::set_var("KAPSARO_WORKSPACE", workspace.path());

    let report = execute_doctor_command(DoctorRequest {
        workspace: None,
        home: Some(home.path().to_path_buf()),
        member_handle: Some("alice@example.com".to_string()),
        debug: false,
        verbose: false,
    })
    .unwrap();

    assert!(report
        .checks()
        .iter()
        .any(|check| check.id == "workspace.structure" && check.status == DoctorStatus::Fail));
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn test_doctor_reports_config_workspace_structure_failure() {
    let _guard = EnvGuard::new(&["KAPSARO_WORKSPACE"]);
    let workspace = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    fs::create_dir_all(workspace.path().join("members/active")).unwrap();
    fs::write(
        home.path().join("config.toml"),
        format!("workspace = \"{}\"\n", workspace.path().display()),
    )
    .unwrap();
    std::env::remove_var("KAPSARO_WORKSPACE");

    let report = execute_doctor_command(DoctorRequest {
        workspace: None,
        home: Some(home.path().to_path_buf()),
        member_handle: Some("alice@example.com".to_string()),
        debug: false,
        verbose: false,
    })
    .unwrap();

    assert!(report
        .checks()
        .iter()
        .any(|check| check.id == "workspace.structure" && check.status == DoctorStatus::Fail));
    assert_eq!(report.exit_code(), 1);
}
