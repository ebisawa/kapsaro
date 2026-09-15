// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Read-only diagnostics for independently resolved workspace and local state targets.
//! Preserves partial failures and reuses the caller's opened workspace capabilities.

pub mod artifacts;
pub mod ci;
pub mod local_state;
pub mod members;
pub mod types;
pub mod workspace;

use std::path::PathBuf;

use self::types::{
    DoctorCategory, DoctorCheck, DoctorReport, DoctorSubject, DoctorTarget, DoctorTargetKind,
};
use crate::error::LOCAL_STATE_PATH_UNSAFE_RECOVERY;
use crate::service::config::LocalStateSession;
use crate::service::workspace::{WorkspaceAccess, WorkspaceKind};
use crate::support::warning::clear_local_state_warnings;
use crate::{Error, ErrorKind, Result};

pub struct DoctorRequest {
    pub local_state: Result<LocalStateSession>,
    pub workspaces: Vec<DoctorWorkspaceResolution>,
    pub member_handle: Result<Option<String>>,
    pub ci: ci::DoctorCiReadiness,
}

impl std::fmt::Debug for DoctorRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DoctorRequest")
            .field(
                "local_state",
                &self.local_state.as_ref().map(LocalStateSession::base_dir),
            )
            .field("workspaces", &self.workspaces)
            .field("member_handle", &self.member_handle)
            .field("ci", &self.ci)
            .finish()
    }
}

/// Each selection retains either its opened directory or its resolution failure.
#[derive(Debug)]
pub enum DoctorWorkspaceResolution {
    Selection {
        access: WorkspaceAccess,
        source: DoctorWorkspaceSource,
    },
    Missing {
        path: Option<PathBuf>,
        source: DoctorWorkspaceSource,
        kind: WorkspaceKind,
    },
    Failure {
        error: Error,
        source: DoctorWorkspaceSource,
        kind: WorkspaceKind,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorWorkspaceSource {
    Cli,
    Environment,
    Config,
    AutoDetect,
    Global,
}

impl DoctorWorkspaceSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "CLI option",
            Self::Environment => "environment variable",
            Self::Config => "global configuration",
            Self::AutoDetect => "auto-detection",
            Self::Global => "HOME",
        }
    }
}

impl DoctorWorkspaceResolution {
    fn target(&self) -> DoctorTarget {
        let (kind, source, path) = match self {
            Self::Selection { access, source } => (access.kind(), *source, Some(access.path())),
            Self::Missing { path, source, kind } => (*kind, *source, path.as_deref()),
            Self::Failure { source, kind, .. } => (*kind, *source, None),
        };
        DoctorTarget {
            kind: if kind == WorkspaceKind::Global {
                DoctorTargetKind::GlobalWorkspace
            } else {
                DoctorTargetKind::Workspace
            },
            sources: vec![source],
            path: path.map(|path| path.to_string_lossy().into_owned()),
        }
    }
}

pub fn execute_doctor_command(request: DoctorRequest) -> Result<DoctorReport> {
    let report = build_doctor_report(request);
    clear_local_state_warnings();
    report
}

fn build_doctor_report(request: DoctorRequest) -> Result<DoctorReport> {
    let DoctorRequest {
        workspaces,
        local_state,
        member_handle,
        ci,
    } = request;
    let WorkspaceTargets {
        resolutions: workspaces,
        mut targets,
        failures,
    } = merge_workspace_targets(workspaces);
    let local_target = targets.len();
    targets.push(DoctorTarget {
        kind: DoctorTargetKind::LocalState,
        sources: Vec::new(),
        path: local_state
            .as_ref()
            .ok()
            .map(|state| state.base_dir().to_string_lossy().into_owned()),
    });
    let mut report = DoctorReport::new(targets);
    report.select_target(local_target);
    let local = collect_local_state(&mut report, &local_state, &member_handle, &ci);
    for (index, resolution) in workspaces.iter().enumerate() {
        report.select_target(index);
        for (_, error) in failures.iter().filter(|(target, _)| *target == index) {
            report.extend([diagnostic_failure(
                "workspace.identity",
                DoctorCategory::Workspace,
                error,
            )]);
        }
        collect_workspace(&mut report, resolution, local.as_ref());
    }
    report.select_target(local_target);
    report.extend(ci::check_ci_readiness(ci));
    Ok(report)
}

struct WorkspaceTargets {
    resolutions: Vec<DoctorWorkspaceResolution>,
    targets: Vec<DoctorTarget>,
    failures: Vec<(usize, Error)>,
}

fn find_duplicate_workspace(
    inputs: &[DoctorWorkspaceResolution],
    input: &DoctorWorkspaceResolution,
) -> Result<Option<usize>> {
    let DoctorWorkspaceResolution::Selection { access, .. } = input else {
        return Ok(None);
    };
    for (index, existing) in inputs.iter().enumerate() {
        if let DoctorWorkspaceResolution::Selection { access: other, .. } = existing {
            if access.same_directory(other)? {
                return Ok(Some(index));
            }
        }
    }
    Ok(None)
}

fn merge_workspace_targets(inputs: Vec<DoctorWorkspaceResolution>) -> WorkspaceTargets {
    let mut resolutions: Vec<DoctorWorkspaceResolution> = Vec::new();
    let mut targets: Vec<DoctorTarget> = Vec::new();
    let mut failures = Vec::new();
    for input in inputs {
        let duplicate = match find_duplicate_workspace(&resolutions, &input) {
            Ok(duplicate) => duplicate,
            Err(error) => {
                failures.push((targets.len(), error));
                None
            }
        };
        let target = input.target();
        if let Some(index) = duplicate {
            targets[index].sources.extend(target.sources);
            if target.kind == DoctorTargetKind::GlobalWorkspace {
                targets[index].kind = target.kind;
                resolutions[index] = input;
            }
        } else {
            targets.push(target);
            resolutions.push(input);
        }
    }
    WorkspaceTargets {
        resolutions,
        targets,
        failures,
    }
}

fn collect_local_state(
    report: &mut DoctorReport,
    local_state: &Result<LocalStateSession>,
    member_handle: &Result<Option<String>>,
    ci: &ci::DoctorCiReadiness,
) -> Option<local_state::LocalStateDiagnostics> {
    if let Err(error) = member_handle {
        report.extend([diagnostic_failure(
            "local_state.owner.resolve",
            DoctorCategory::LocalState,
            error,
        )]);
    }
    let session = match local_state {
        Ok(session) => session,
        Err(error) => {
            let mut check =
                diagnostic_failure("local_state.resolve", DoctorCategory::LocalState, error);
            if matches!(error.kind(), ErrorKind::Io | ErrorKind::InvalidOperation) {
                check = check
                    .with_rule(
                        error
                            .recovery()
                            .or_else(|| error.rule())
                            .or(Some(LOCAL_STATE_PATH_UNSAFE_RECOVERY)),
                    )
                    .with_next_action("inspect the local state path and permissions");
            }
            report.extend([check]);
            return None;
        }
    };
    let owner = member_handle
        .as_ref()
        .ok()
        .and_then(|value| value.as_deref());
    let fallback = member_handle.is_ok() && matches!(ci, ci::DoctorCiReadiness::Inactive);
    match local_state::check_local_state(session, owner, fallback) {
        Ok(mut local) => {
            report.extend(std::mem::take(&mut local.checks));
            report.extend(local_state::check_trust_store(
                session.base_dir(),
                &mut local,
            ));
            Some(local)
        }
        Err(error) => {
            report.extend([diagnostic_failure(
                "local_state.inspect",
                DoctorCategory::LocalState,
                &error,
            )]);
            None
        }
    }
}

fn collect_workspace(
    report: &mut DoctorReport,
    resolution: &DoctorWorkspaceResolution,
    local: Option<&local_state::LocalStateDiagnostics>,
) {
    let mut state = workspace::check_workspace(resolution);
    report.extend(std::mem::take(&mut state.checks));
    let Some(directory) = state.scoped_workspace() else {
        return;
    };
    extend_diagnostic_result(
        report,
        "members.inspect",
        DoctorCategory::MembersActive,
        members::check_members(directory),
    );
    if let Some(local) = local {
        if let (Some(owner), Some(known_keys)) = (local.owner.as_ref(), local.known_keys.as_ref()) {
            extend_diagnostic_result(
                report,
                "trust.inspect",
                DoctorCategory::LocalTrustStore,
                local_state::check_active_member_approvals(directory, owner.as_str(), known_keys),
            );
        }
    }
    extend_diagnostic_result(
        report,
        "artifacts.inspect",
        DoctorCategory::Artifacts,
        artifacts::check_artifacts(directory),
    );
}

fn extend_diagnostic_result(
    report: &mut DoctorReport,
    id: &'static str,
    category: DoctorCategory,
    checks: Result<Vec<DoctorCheck>>,
) {
    match checks {
        Ok(checks) => report.extend(checks),
        Err(error) => report.extend([diagnostic_failure(id, category, &error)]),
    }
}

fn diagnostic_failure(id: &'static str, category: DoctorCategory, error: &Error) -> DoctorCheck {
    DoctorCheck::fail(
        id,
        category,
        DoctorSubject::General(category.title().to_string()),
        "Diagnostic input or inspection failed",
    )
    .with_reason(error.format_user_message())
    .with_rule(error.recovery().or_else(|| error.rule()))
}

#[cfg(test)]
#[path = "../../tests/unit/internal/service_doctor_test.rs"]
mod service_doctor_test;
