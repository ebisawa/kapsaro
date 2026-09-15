// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::service::config::LocalStateSession;
use crate::service::doctor::ci::DoctorCiReadiness;
use crate::service::doctor::types::DoctorStatus;
use crate::service::doctor::{
    execute_doctor_command, DoctorRequest, DoctorWorkspaceResolution, DoctorWorkspaceSource,
};
use crate::service::workspace::{WorkspaceAccess, WorkspaceKind};
use tempfile::TempDir;

fn initialized_workspace() -> TempDir {
    let workspace = TempDir::new().unwrap();
    for path in ["members/active", "members/incoming", "secrets"] {
        std::fs::create_dir_all(workspace.path().join(path)).unwrap();
    }
    workspace
}

#[cfg(unix)]
#[test]
fn test_doctor_distinguishes_global_permissions_from_unsafe_entries() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let global = initialized_workspace();
    let local = TempDir::new().unwrap();
    let exposed = global.path().join("secrets/exposed.txt");
    std::fs::write(&exposed, "preserved contents").unwrap();
    std::fs::set_permissions(&exposed, std::fs::Permissions::from_mode(0o644)).unwrap();
    symlink(&exposed, global.path().join("secrets/link")).unwrap();
    let report = execute_doctor_command(DoctorRequest {
        workspaces: vec![DoctorWorkspaceResolution::Selection {
            access: WorkspaceAccess::open(global.path(), WorkspaceKind::Global).unwrap(),
            source: DoctorWorkspaceSource::Global,
        }],
        local_state: LocalStateSession::open(local.path()),
        member_handle: Ok(None),
        ci: DoctorCiReadiness::Inactive,
    })
    .unwrap();
    let checks: Vec<_> = report
        .checks()
        .iter()
        .filter(|check| check.id == "global_workspace.permissions")
        .collect();
    assert!(checks.iter().any(|check| check.status == DoctorStatus::Warn
        && check.rule.as_deref() == Some("W_GLOBAL_WORKSPACE_PERMISSIONS")));
    assert!(checks
        .iter()
        .any(|check| check.status == DoctorStatus::Fail && check.rule.is_none()));
    assert_eq!(
        std::fs::metadata(&exposed).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(
        std::fs::read_to_string(&exposed).unwrap(),
        "preserved contents"
    );
    assert_eq!(std::fs::read_dir(local.path()).unwrap().count(), 0);
}

#[test]
fn test_doctor_candidate_search_retains_incomplete_layout_and_excludes_global() {
    use crate::service::workspace::{detect_workspace_candidate_path, WorkspaceCreationTarget};
    let home = TempDir::new().unwrap();
    let global = home.path().join(".kapsaro");
    std::fs::create_dir(&global).unwrap();
    assert_eq!(
        detect_workspace_candidate_path(home.path(), None).unwrap(),
        global.canonicalize().unwrap()
    );
    let excluded = WorkspaceCreationTarget::open(&global, WorkspaceKind::Global).unwrap();
    assert_eq!(
        detect_workspace_candidate_path(home.path(), Some(&excluded))
            .unwrap_err()
            .kind(),
        crate::ErrorKind::NotFound
    );
}

#[test]
fn test_doctor_reports_both_workspace_targets_and_common_state_once() {
    let regular = initialized_workspace();
    let global = initialized_workspace();
    let home = TempDir::new().unwrap();
    let report = execute_doctor_command(DoctorRequest {
        workspaces: vec![
            build_workspace_resolution(regular.path(), DoctorWorkspaceSource::AutoDetect),
            DoctorWorkspaceResolution::Selection {
                access: WorkspaceAccess::open(global.path(), WorkspaceKind::Global).unwrap(),
                source: DoctorWorkspaceSource::Global,
            },
        ],
        local_state: LocalStateSession::open(home.path().to_path_buf()),
        member_handle: Ok(Some("alice@example.com".to_string())),
        ci: DoctorCiReadiness::Inactive,
    })
    .unwrap();
    assert_eq!(report.targets().len(), 3);
    assert_eq!(
        report
            .checks()
            .iter()
            .filter(|check| check.id == "keystore.root")
            .count(),
        1
    );
    assert_eq!(
        report
            .checks()
            .iter()
            .filter(|check| check.id == "trust_store.present")
            .count(),
        1
    );
    for target in [0, 1] {
        assert!(report
            .checks()
            .iter()
            .any(|check| check.target == Some(target) && check.id == "members.incoming.empty"));
    }
    assert!(report.checks().iter().any(|check| check.target == Some(1)
        && check.id == "workspace.gitless"
        && check.status == DoctorStatus::Ok));
}

#[test]
fn test_doctor_merges_alias_targets_and_retains_global_kind_and_sources() {
    use crate::service::doctor::types::DoctorTargetKind;
    let workspace = initialized_workspace();
    let home = TempDir::new().unwrap();
    let report = execute_doctor_command(DoctorRequest {
        workspaces: vec![
            build_workspace_resolution(workspace.path(), DoctorWorkspaceSource::Cli),
            DoctorWorkspaceResolution::Selection {
                access: WorkspaceAccess::open(workspace.path().join("."), WorkspaceKind::Global)
                    .unwrap(),
                source: DoctorWorkspaceSource::Global,
            },
        ],
        local_state: LocalStateSession::open(home.path().to_path_buf()),
        member_handle: Ok(None),
        ci: DoctorCiReadiness::Inactive,
    })
    .unwrap();
    assert_eq!(report.targets().len(), 2);
    assert_eq!(report.targets()[0].kind, DoctorTargetKind::GlobalWorkspace);
    assert_eq!(
        report.targets()[0].sources,
        vec![DoctorWorkspaceSource::Cli, DoctorWorkspaceSource::Global]
    );
    assert_eq!(
        report
            .checks()
            .iter()
            .filter(|check| check.id == "workspace.structure")
            .count(),
        1
    );
}

#[test]
fn test_doctor_continues_workspace_checks_after_local_and_global_resolution_failures() {
    let workspace = initialized_workspace();
    let report = execute_doctor_command(DoctorRequest {
        workspaces: vec![
            build_workspace_resolution(workspace.path(), DoctorWorkspaceSource::Cli),
            DoctorWorkspaceResolution::Failure {
                error: crate::Error::build_config_error("HOME must be absolute"),
                source: DoctorWorkspaceSource::Global,
                kind: WorkspaceKind::Global,
            },
        ],
        local_state: Err(crate::Error::build_config_error("local state unavailable")),
        member_handle: Err(crate::Error::build_config_error(
            "invalid owner configuration",
        )),
        ci: DoctorCiReadiness::Inactive,
    })
    .unwrap();
    assert_eq!(report.exit_code(), 1);
    for id in [
        "local_state.resolve",
        "local_state.owner.resolve",
        "workspace.resolve",
        "members.incoming.empty",
    ] {
        assert!(report.checks().iter().any(|check| check.id == id), "{id}");
    }
    assert!(report
        .checks()
        .iter()
        .any(|check| check.target == Some(1) && check.status == DoctorStatus::Fail));
}

#[test]
fn test_doctor_keeps_selected_root_after_path_replacement() {
    let workspace = initialized_workspace();
    let home = TempDir::new().unwrap();
    let access = WorkspaceAccess::open(workspace.path(), WorkspaceKind::Global).unwrap();
    let moved = workspace.path().with_extension("doctor-moved");
    std::fs::rename(workspace.path(), &moved).unwrap();
    std::fs::create_dir(workspace.path()).unwrap();
    let report = execute_doctor_command(DoctorRequest {
        workspaces: vec![DoctorWorkspaceResolution::Selection {
            access,
            source: DoctorWorkspaceSource::Global,
        }],
        local_state: LocalStateSession::open(home.path().to_path_buf()),
        member_handle: Ok(None),
        ci: DoctorCiReadiness::Inactive,
    })
    .unwrap();
    assert!(report
        .checks()
        .iter()
        .any(|check| check.id == "workspace.structure" && check.status == DoctorStatus::Ok));
    std::fs::remove_dir_all(moved).unwrap();
}

#[test]
fn test_doctor_keeps_local_state_selected_before_path_replacement() {
    let parent = TempDir::new().unwrap();
    let home = parent.path().join("home");
    std::fs::create_dir_all(home.join("keys")).unwrap();
    let local_state = LocalStateSession::open(&home).unwrap();
    std::fs::rename(&home, parent.path().join("original")).unwrap();
    std::fs::create_dir(&home).unwrap();
    let report = execute_doctor_command(DoctorRequest {
        local_state: Ok(local_state),
        workspaces: Vec::new(),
        member_handle: Ok(None),
        ci: DoctorCiReadiness::Inactive,
    })
    .unwrap();
    assert!(report
        .checks()
        .iter()
        .any(|check| check.id == "keystore.root" && check.status == DoctorStatus::Ok));
}

fn build_workspace_resolution(
    path: impl Into<std::path::PathBuf>,
    source: DoctorWorkspaceSource,
) -> DoctorWorkspaceResolution {
    DoctorWorkspaceResolution::Selection {
        access: WorkspaceAccess::open(path.into(), WorkspaceKind::Regular).unwrap(),
        source,
    }
}

#[test]
fn test_doctor_reports_selected_workspace_structure_failure() {
    for (source, label, partial) in [
        (DoctorWorkspaceSource::Cli, "CLI option", false),
        (
            DoctorWorkspaceSource::Environment,
            "environment variable",
            true,
        ),
        (DoctorWorkspaceSource::Config, "global configuration", true),
    ] {
        let workspace = TempDir::new().unwrap();
        let home = TempDir::new().unwrap();
        if partial {
            std::fs::create_dir_all(workspace.path().join("members/active")).unwrap();
        }
        let report = execute_doctor_command(DoctorRequest {
            workspaces: vec![build_workspace_resolution(workspace.path(), source)],
            local_state: LocalStateSession::open(home.path().to_path_buf()),
            member_handle: Ok(Some("alice@example.com".to_string())),
            ci: DoctorCiReadiness::Inactive,
        })
        .unwrap();
        assert!(
            report.checks().iter().any(
                |check| check.id == "workspace.structure" && check.status == DoctorStatus::Fail
            ),
            "{label}"
        );
        assert!(
            report
                .checks()
                .iter()
                .any(|check| check.id == "workspace.resolve"
                    && check.status == DoctorStatus::Ok
                    && check.message.contains(label)),
            "{label}"
        );
        assert_eq!(report.exit_code(), 1, "{label}");
    }
}

#[test]
fn test_doctor_reports_empty_incoming_as_ok() {
    let workspace = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace.path().join("members/incoming")).unwrap();
    std::fs::create_dir_all(workspace.path().join("secrets")).unwrap();

    let report = execute_doctor_command(DoctorRequest {
        workspaces: vec![build_workspace_resolution(
            workspace.path(),
            DoctorWorkspaceSource::Cli,
        )],
        local_state: LocalStateSession::open(home.path().to_path_buf()),
        member_handle: Ok(Some("alice@example.com".to_string())),
        ci: DoctorCiReadiness::Inactive,
    })
    .unwrap();

    assert!(report
        .checks()
        .iter()
        .any(|check| check.id == "members.incoming.empty" && check.status == DoctorStatus::Ok));
}

#[test]
fn test_doctor_reports_auto_detected_workspace_source() {
    let workspace = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace.path().join("members/incoming")).unwrap();
    std::fs::create_dir_all(workspace.path().join("secrets")).unwrap();

    let report = execute_doctor_command(DoctorRequest {
        workspaces: vec![build_workspace_resolution(
            workspace.path(),
            DoctorWorkspaceSource::AutoDetect,
        )],
        local_state: LocalStateSession::open(home.path().to_path_buf()),
        member_handle: Ok(Some("alice@example.com".to_string())),
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
        workspaces: vec![DoctorWorkspaceResolution::Missing {
            path: None,
            source: DoctorWorkspaceSource::AutoDetect,
            kind: WorkspaceKind::Regular,
        }],
        local_state: LocalStateSession::open(home.path().to_path_buf()),
        member_handle: Ok(Some("alice@example.com".to_string())),
        ci: DoctorCiReadiness::Inactive,
    })
    .unwrap();

    assert!(report
        .checks()
        .iter()
        .any(|check| check.id == "workspace.resolve" && check.status == DoctorStatus::Skip));
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
        workspaces: vec![DoctorWorkspaceResolution::Failure {
            error,
            source: DoctorWorkspaceSource::Config,
            kind: WorkspaceKind::Regular,
        }],
        local_state: LocalStateSession::open(home.path().to_path_buf()),
        member_handle: Ok(Some("alice@example.com".to_string())),
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
