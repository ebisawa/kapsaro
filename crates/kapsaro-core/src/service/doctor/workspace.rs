// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace diagnostics through the descriptor selected by the caller.
//! Distinguishes unused targets, invalid structures, and global permission findings.

use std::path::Path;

use super::types::{DoctorCategory, DoctorCheck, DoctorStatus, DoctorSubject};
use super::{DoctorWorkspaceResolution, DoctorWorkspaceSource};
use crate::service::workspace::{WorkspaceAccess, WorkspaceKind};
use crate::support::fs::anchor::AnchoredDir;
use crate::support::path::format_path_relative_to_cwd;
use crate::Error;

pub struct DoctorWorkspaceState {
    workspace_dir: Option<AnchoredDir>,
    pub checks: Vec<DoctorCheck>,
}

impl DoctorWorkspaceState {
    pub(crate) fn scoped_workspace(&self) -> Option<&AnchoredDir> {
        self.workspace_dir.as_ref()
    }
}

pub fn check_workspace(resolution: &DoctorWorkspaceResolution) -> DoctorWorkspaceState {
    match resolution {
        DoctorWorkspaceResolution::Selection { access, source } => {
            inspect_workspace(access, *source)
        }
        DoctorWorkspaceResolution::Missing { path, kind, source } => DoctorWorkspaceState {
            workspace_dir: None,
            checks: vec![DoctorCheck::new(
                "workspace.resolve",
                DoctorCategory::Workspace,
                if matches!(
                    source,
                    DoctorWorkspaceSource::AutoDetect | DoctorWorkspaceSource::Global
                ) {
                    DoctorStatus::Skip
                } else {
                    DoctorStatus::Fail
                },
                DoctorSubject::Path(
                    path.as_ref()
                        .map(|path| format_path_relative_to_cwd(path))
                        .unwrap_or_else(|| "(unresolved)".to_string()),
                ),
                if matches!(
                    source,
                    DoctorWorkspaceSource::AutoDetect | DoctorWorkspaceSource::Global
                ) {
                    "Workspace is not in use"
                } else {
                    "Selected workspace does not exist"
                },
            )
            .with_next_action(if *kind == WorkspaceKind::Global {
                "optionally run kapsaro init --global"
            } else {
                "optionally select a workspace with --workspace"
            })],
        },
        DoctorWorkspaceResolution::Failure { error, .. } => DoctorWorkspaceState {
            workspace_dir: None,
            checks: vec![resolution_failure(error)],
        },
    }
}

fn inspect_workspace(
    access: &WorkspaceAccess,
    source: DoctorWorkspaceSource,
) -> DoctorWorkspaceState {
    let mut checks = vec![DoctorCheck::ok(
        "workspace.resolve",
        DoctorCategory::Workspace,
        DoctorSubject::Path(format_path_relative_to_cwd(access.path())),
        format!("Workspace resolved from {}", source.as_str()),
    )];
    let directory = access.directory();
    let structure = check_structure(directory, access.path());
    let structure_ok = structure.status == DoctorStatus::Ok;
    checks.push(structure);
    if access.kind() == WorkspaceKind::Global {
        checks.push(DoctorCheck::ok(
            "workspace.gitless",
            DoctorCategory::Workspace,
            DoctorSubject::Path(format_path_relative_to_cwd(access.path())),
            "Global workspace does not require a git checkout",
        ));
        checks.extend(check_global_permissions(directory));
    } else if is_gitless_layout(access.path()) {
        checks.push(
            DoctorCheck::warn(
                "workspace.gitless",
                DoctorCategory::Workspace,
                DoctorSubject::Path(format_path_relative_to_cwd(access.path())),
                "Workspace is not inside a git checkout",
            )
            .with_next_action("confirm this production layout is intentional"),
        );
    }
    DoctorWorkspaceState {
        workspace_dir: structure_ok.then(|| directory.clone()),
        checks,
    }
}

fn check_structure(directory: &AnchoredDir, path: &Path) -> DoctorCheck {
    let mut failures = Vec::new();
    for components in [
        &["members", "active"][..],
        &["members", "incoming"][..],
        &["secrets"][..],
    ] {
        let result = components
            .iter()
            .try_fold(directory.clone(), |parent, name| parent.open_child(name));
        if let Err(error) = result {
            failures.push(error.format_user_message().to_owned());
        }
    }
    let subject = DoctorSubject::Path(format_path_relative_to_cwd(path));
    if failures.is_empty() {
        DoctorCheck::ok(
            "workspace.structure",
            DoctorCategory::Workspace,
            subject,
            "Workspace has members/active, members/incoming, and secrets",
        )
    } else {
        DoctorCheck::fail(
            "workspace.structure",
            DoctorCategory::Workspace,
            subject,
            "Workspace directories are missing or could not be inspected",
        )
        .with_reason_names(failures)
        .with_next_action("run kapsaro init or repair the workspace")
    }
}

fn resolution_failure(error: &Error) -> DoctorCheck {
    DoctorCheck::fail(
        "workspace.resolve",
        DoctorCategory::Workspace,
        DoctorSubject::General("workspace".to_string()),
        "Workspace could not be resolved",
    )
    .with_reason(error.format_user_message())
    .with_next_action("fix HOME or the workspace configuration, then run the diagnosis again")
    .with_rule(error.recovery().or_else(|| error.rule()))
}

#[cfg(unix)]
fn check_global_permissions(directory: &AnchoredDir) -> Vec<DoctorCheck> {
    use crate::support::fs::permission::{
        collect_local_state_tree_violations, PermissionViolationKind,
    };
    collect_local_state_tree_violations(directory).into_iter().map(|finding| {
        let status = match finding.kind() {
            PermissionViolationKind::InsecureMode | PermissionViolationKind::ForeignOwner => DoctorStatus::Warn,
            _ => DoctorStatus::Fail,
        };
        DoctorCheck::new("global_workspace.permissions", DoctorCategory::Workspace, status,
            DoctorSubject::Path(format_path_relative_to_cwd(finding.path())), finding.message())
            .with_next_action(if status == DoctorStatus::Warn {
                "restore ownership to the current user and restrict directories to 0700 and files to 0600"
            } else {
                "repair the reported path or I/O failure, then run kapsaro doctor again"
            })
            .with_rule((status == DoctorStatus::Warn).then_some("W_GLOBAL_WORKSPACE_PERMISSIONS"))
    }).collect()
}

#[cfg(not(unix))]
fn check_global_permissions(_directory: &AnchoredDir) -> Vec<DoctorCheck> {
    Vec::new()
}

fn is_gitless_layout(workspace_root: &Path) -> bool {
    !workspace_root
        .ancestors()
        .any(|path| path.join(".git").exists())
}
