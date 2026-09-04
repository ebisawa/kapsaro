// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::service::doctor::ci::DoctorCiReadiness;
use crate::service::doctor::types::DoctorStatus;
use crate::service::doctor::{
    execute_doctor_command, DoctorRequest, DoctorWorkspaceResolution, DoctorWorkspaceSource,
};
use tempfile::TempDir;

fn build_workspace_resolution(
    path: impl Into<std::path::PathBuf>,
    source: DoctorWorkspaceSource,
) -> DoctorWorkspaceResolution {
    DoctorWorkspaceResolution::Selection {
        path: path.into(),
        source,
    }
}

#[test]
fn test_doctor_reports_missing_workspace_structure_as_fail() {
    let workspace = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();

    let report = execute_doctor_command(DoctorRequest {
        workspace: build_workspace_resolution(workspace.path(), DoctorWorkspaceSource::Cli),
        base_dir: home.path().to_path_buf(),
        member_handle: Some("alice@example.com".to_string()),
        ci: DoctorCiReadiness::Inactive,
    })
    .unwrap();

    assert!(report
        .checks()
        .iter()
        .any(|check| check.id == "workspace.structure" && check.status == DoctorStatus::Fail));
    assert!(report.checks().iter().any(|check| {
        check.id == "workspace.resolve"
            && check.status == DoctorStatus::Ok
            && check.message.contains("CLI option")
    }));
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
        workspace: build_workspace_resolution(workspace.path(), DoctorWorkspaceSource::Cli),
        base_dir: home.path().to_path_buf(),
        member_handle: Some("alice@example.com".to_string()),
        ci: DoctorCiReadiness::Inactive,
    })
    .unwrap();

    assert!(report
        .checks()
        .iter()
        .any(|check| check.id == "members.incoming.empty" && check.status == DoctorStatus::Ok));
}

#[test]
fn test_doctor_reports_environment_selected_workspace_structure_failure() {
    let workspace = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace.path().join("members/active")).unwrap();

    let report = execute_doctor_command(DoctorRequest {
        workspace: build_workspace_resolution(workspace.path(), DoctorWorkspaceSource::Environment),
        base_dir: home.path().to_path_buf(),
        member_handle: Some("alice@example.com".to_string()),
        ci: DoctorCiReadiness::Inactive,
    })
    .unwrap();

    assert!(report
        .checks()
        .iter()
        .any(|check| check.id == "workspace.structure" && check.status == DoctorStatus::Fail));
    assert!(report.checks().iter().any(|check| {
        check.id == "workspace.resolve"
            && check.status == DoctorStatus::Ok
            && check.message.contains("environment variable")
    }));
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn test_doctor_reports_config_selected_workspace_structure_failure() {
    let workspace = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace.path().join("members/active")).unwrap();

    let report = execute_doctor_command(DoctorRequest {
        workspace: build_workspace_resolution(workspace.path(), DoctorWorkspaceSource::Config),
        base_dir: home.path().to_path_buf(),
        member_handle: Some("alice@example.com".to_string()),
        ci: DoctorCiReadiness::Inactive,
    })
    .unwrap();

    assert!(report
        .checks()
        .iter()
        .any(|check| check.id == "workspace.structure" && check.status == DoctorStatus::Fail));
    assert!(report.checks().iter().any(|check| {
        check.id == "workspace.resolve"
            && check.status == DoctorStatus::Ok
            && check.message.contains("global configuration")
    }));
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn test_doctor_reports_auto_detected_workspace_source() {
    let workspace = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace.path().join("members/incoming")).unwrap();
    std::fs::create_dir_all(workspace.path().join("secrets")).unwrap();

    let report = execute_doctor_command(DoctorRequest {
        workspace: build_workspace_resolution(workspace.path(), DoctorWorkspaceSource::AutoDetect),
        base_dir: home.path().to_path_buf(),
        member_handle: Some("alice@example.com".to_string()),
        ci: DoctorCiReadiness::Inactive,
    })
    .unwrap();

    assert!(report.checks().iter().any(|check| {
        check.id == "workspace.resolve"
            && check.status == DoctorStatus::Ok
            && check.message.contains("auto-detection")
    }));
    assert!(report
        .checks()
        .iter()
        .any(|check| check.id == "members.incoming.empty" && check.status == DoctorStatus::Ok));
}

#[test]
fn test_doctor_uses_unresolved_workspace_and_continues_diagnostics() {
    let home = TempDir::new().unwrap();

    let report = execute_doctor_command(DoctorRequest {
        workspace: DoctorWorkspaceResolution::Unresolved,
        base_dir: home.path().to_path_buf(),
        member_handle: Some("alice@example.com".to_string()),
        ci: DoctorCiReadiness::Inactive,
    })
    .unwrap();

    assert!(report
        .checks()
        .iter()
        .any(|check| check.id == "workspace.resolve" && check.status == DoctorStatus::Fail));
    assert!(report
        .checks()
        .iter()
        .any(|check| check.id == "keystore.root" && check.status == DoctorStatus::Warn));
}

#[test]
fn test_doctor_reports_workspace_resolution_failure_and_continues_diagnostics() {
    let home = TempDir::new().unwrap();
    let error = crate::Error::build_config_error("invalid configured workspace");

    let report = execute_doctor_command(DoctorRequest {
        workspace: DoctorWorkspaceResolution::Failure(error),
        base_dir: home.path().to_path_buf(),
        member_handle: Some("alice@example.com".to_string()),
        ci: DoctorCiReadiness::Inactive,
    })
    .unwrap();

    let resolution = report
        .checks()
        .iter()
        .find(|check| check.id == "workspace.resolve")
        .expect("workspace resolution check");
    assert_eq!(resolution.status, DoctorStatus::Fail);
    assert_eq!(
        resolution.reason_line().as_deref(),
        Some("invalid configured workspace")
    );
    assert!(report
        .checks()
        .iter()
        .any(|check| check.id == "keystore.root" && check.status == DoctorStatus::Warn));
}
