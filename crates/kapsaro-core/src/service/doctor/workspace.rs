// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Doctor checks for workspace resolution and directory structure.
//! Confirms the workspace path, its required subdirectories, and whether it sits inside a git checkout.

use std::path::{Path, PathBuf};

use crate::io::config::paths::get_global_config_path_from_base;
use crate::io::keystore::paths::get_keystore_root_from_base;
use crate::io::workspace::detection::WorkspaceRoot;
use crate::io::workspace::members::{ACTIVE_DIR_NAME, INCOMING_DIR_NAME, MEMBERS_DIR_NAME};
use crate::io::workspace::setup::SECRETS_DIR_NAME;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::DirectoryScope;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};

use super::types::{DoctorCategory, DoctorCheck, DoctorSubject};
use super::DoctorWorkspaceResolution;

use crate::support::fs::policy::is_real_dir;

pub struct DoctorWorkspaceState {
    pub workspace_root: Option<WorkspaceRoot>,
    /// The workspace root bound to a descriptor, present once the structure
    /// holds and the root opened. Workspace-scoped checks read through it so
    /// they answer from the tree this run started in.
    pub(crate) workspace_dir: Option<AnchoredDir>,
    pub structure_ok: bool,
    pub checks: Vec<DoctorCheck>,
}

impl DoctorWorkspaceState {
    pub fn workspace_display(&self) -> String {
        self.workspace_root
            .as_ref()
            .map(|workspace| format_path_relative_to_cwd(&workspace.root_path))
            .unwrap_or_else(|| "(unresolved)".to_string())
    }

    /// The workspace the scoped checks may run against, once it resolved, held
    /// the required directories, and opened.
    ///
    /// Every one of those checks reads through this descriptor, so the report
    /// they build describes one tree even if the workspace path is repointed
    /// while the diagnosis runs.
    pub(crate) fn scoped_workspace(&self) -> Option<&AnchoredDir> {
        if !self.structure_ok {
            return None;
        }
        self.workspace_dir.as_ref()
    }
}

pub fn check_workspace(
    base_dir: &Path,
    resolution: &DoctorWorkspaceResolution,
) -> DoctorWorkspaceState {
    let keystore_root = get_keystore_root_from_base(base_dir);
    let config_path = get_global_config_path_from_base(base_dir);
    let mut checks = vec![build_workspace_paths_check(
        base_dir,
        &keystore_root,
        &config_path,
    )];

    let (workspace, source) = match resolution {
        DoctorWorkspaceResolution::Selection { path, source } => (path, source),
        DoctorWorkspaceResolution::Unresolved => {
            checks.push(check_unresolved_workspace());
            return build_workspace_state(None, None, false, checks);
        }
        DoctorWorkspaceResolution::Failure(error) => {
            checks.push(build_workspace_resolution_failure_check(error));
            return build_workspace_state(None, None, false, checks);
        }
    };
    let workspace_root = match canonicalize_doctor_workspace(workspace) {
        Ok(workspace_root) => workspace_root,
        Err(error) => {
            checks.push(build_workspace_resolution_failure_check(&error));
            return build_workspace_state(None, None, false, checks);
        }
    };

    checks.push(check_resolved_workspace(&workspace_root, source.as_str()));
    inspect_resolved_workspace(workspace_root, checks)
}

/// Judge the structure of a workspace that resolved, then bind it to the
/// descriptor the workspace-scoped checks read through.
fn inspect_resolved_workspace(
    workspace_root: WorkspaceRoot,
    mut checks: Vec<DoctorCheck>,
) -> DoctorWorkspaceState {
    let structure = inspect_workspace_structure(&workspace_root.root_path);
    checks.push(check_workspace_structure(
        &workspace_root.root_path,
        &structure,
    ));
    checks.extend(check_gitless_workspace(&workspace_root.root_path));
    if !structure.holds() {
        return build_workspace_state(Some(workspace_root), None, false, checks);
    }

    let (workspace_dir, open_check) = bind_doctor_workspace(&workspace_root.root_path);
    checks.extend(open_check);
    let structure_ok = workspace_dir.is_some();
    build_workspace_state(Some(workspace_root), workspace_dir, structure_ok, checks)
}

/// Open the workspace root the later checks address their reads to.
///
/// A root that resolved and holds the required directories is expected to open,
/// so a failure here is reported as a finding of its own and the checks that
/// need the descriptor are left out rather than answered from a path resolved a
/// second time.
fn bind_doctor_workspace(workspace_root: &Path) -> (Option<AnchoredDir>, Option<DoctorCheck>) {
    match AnchoredDir::open(
        workspace_root.to_path_buf(),
        DirectoryScope::Generic,
        "workspace root",
    ) {
        Ok(opened) => (Some(opened), None),
        Err(error) => (
            None,
            Some(DoctorCheck::fail_with_reason_and_next_action(
                "workspace.open",
                DoctorCategory::Workspace,
                DoctorSubject::Path(format_path_relative_to_cwd(workspace_root)),
                "Workspace root could not be opened",
                error.format_user_message(),
                "make the workspace root readable, then run the diagnosis again",
            )),
        ),
    }
}

fn build_workspace_paths_check(
    base_dir: &Path,
    keystore_root: &Path,
    config_path: &Path,
) -> DoctorCheck {
    DoctorCheck::ok(
        "config.paths",
        DoctorCategory::Workspace,
        DoctorSubject::Path(format_path_relative_to_cwd(base_dir)),
        format!(
            "Home: {}; keystore: {}; config: {}",
            format_path_relative_to_cwd(base_dir),
            format_path_relative_to_cwd(keystore_root),
            format_path_relative_to_cwd(config_path)
        ),
    )
}

fn check_unresolved_workspace() -> DoctorCheck {
    DoctorCheck::fail(
        "workspace.resolve",
        DoctorCategory::Workspace,
        DoctorSubject::General("workspace".to_string()),
        "Workspace could not be resolved",
    )
    .with_next_action("specify --workspace or run from a workspace root")
}

fn build_workspace_resolution_failure_check(error: &Error) -> DoctorCheck {
    DoctorCheck::fail_with_reason_and_next_action(
        "workspace.resolve",
        DoctorCategory::Workspace,
        DoctorSubject::General("workspace".to_string()),
        "Workspace could not be resolved",
        error.format_user_message(),
        "fix the workspace configuration or specify --workspace",
    )
    .with_rule(error.recovery().or_else(|| error.rule()))
}

fn check_resolved_workspace(workspace_root: &WorkspaceRoot, source: &str) -> DoctorCheck {
    DoctorCheck::ok(
        "workspace.resolve",
        DoctorCategory::Workspace,
        DoctorSubject::Path(format_path_relative_to_cwd(&workspace_root.root_path)),
        format!("Workspace resolved from {}", source),
    )
}

fn check_gitless_workspace(workspace_root: &Path) -> Vec<DoctorCheck> {
    if !is_gitless_layout(workspace_root) {
        return Vec::new();
    }
    vec![DoctorCheck::warn_with_next_action(
        "workspace.gitless",
        DoctorCategory::Workspace,
        DoctorSubject::Path(format_path_relative_to_cwd(workspace_root)),
        "Workspace is not inside a git checkout",
        "confirm this production layout is intentional",
    )]
}

fn build_workspace_state(
    workspace_root: Option<WorkspaceRoot>,
    workspace_dir: Option<AnchoredDir>,
    structure_ok: bool,
    checks: Vec<DoctorCheck>,
) -> DoctorWorkspaceState {
    DoctorWorkspaceState {
        workspace_root,
        workspace_dir,
        structure_ok,
        checks,
    }
}

fn canonicalize_doctor_workspace(path: &Path) -> Result<WorkspaceRoot> {
    let root_path = path.canonicalize().map_err(|error| {
        Error::build_config_error(format!(
            "Invalid workspace path '{}': {}",
            format_path_relative_to_cwd(path),
            error
        ))
    })?;
    Ok(WorkspaceRoot { root_path })
}

/// What the required directories look like, keeping absence apart from an
/// inspection that could not answer.
struct WorkspaceStructure {
    missing: Vec<String>,
    uninspectable: Vec<String>,
}

impl WorkspaceStructure {
    fn holds(&self) -> bool {
        self.missing.is_empty() && self.uninspectable.is_empty()
    }
}

/// The required directories that are not there, and the ones that could not be
/// looked at.
///
/// An inspection that could not answer is kept apart from a missing directory,
/// because telling the operator to run init would not repair a directory
/// kapsaro is simply not allowed to read. Neither one ends the diagnosis: a
/// failure that escaped here would take every later check down with it.
fn inspect_workspace_structure(workspace_root: &Path) -> WorkspaceStructure {
    let mut missing = Vec::new();
    let mut uninspectable = Vec::new();
    for path in required_workspace_dirs(workspace_root) {
        match is_real_dir(&path) {
            Ok(true) => {}
            Ok(false) => missing.push(format_path_relative_to_cwd(&path)),
            Err(error) => uninspectable.push(format!(
                "{} ({})",
                format_path_relative_to_cwd(&path),
                error.format_user_message()
            )),
        }
    }
    WorkspaceStructure {
        missing,
        uninspectable,
    }
}

fn check_workspace_structure(workspace_root: &Path, structure: &WorkspaceStructure) -> DoctorCheck {
    if structure.holds() {
        return DoctorCheck::ok(
            "workspace.structure",
            DoctorCategory::Workspace,
            DoctorSubject::Path(format_path_relative_to_cwd(workspace_root)),
            "Workspace has members/active, members/incoming, and secrets",
        );
    }
    if !structure.uninspectable.is_empty() {
        return DoctorCheck::fail_with_reason_and_next_action(
            "workspace.structure",
            DoctorCategory::Workspace,
            DoctorSubject::Path(format_path_relative_to_cwd(workspace_root)),
            "Workspace directories could not be inspected",
            format!("uninspectable: {}", structure.uninspectable.join(", ")),
            "make the workspace directories readable, then run the diagnosis again",
        );
    }
    DoctorCheck::fail_with_reason_and_next_action(
        "workspace.structure",
        DoctorCategory::Workspace,
        DoctorSubject::Path(format_path_relative_to_cwd(workspace_root)),
        "Workspace is missing required directories",
        format!("missing: {}", structure.missing.join(", ")),
        "run kapsaro init or repair the workspace",
    )
}

fn required_workspace_dirs(workspace_root: &Path) -> [PathBuf; 3] {
    [
        workspace_root.join(MEMBERS_DIR_NAME).join(ACTIVE_DIR_NAME),
        workspace_root
            .join(MEMBERS_DIR_NAME)
            .join(INCOMING_DIR_NAME),
        workspace_root.join(SECRETS_DIR_NAME),
    ]
}

fn is_gitless_layout(workspace_root: &Path) -> bool {
    let mut current = Some(workspace_root);
    while let Some(path) = current {
        if path.join(".git").exists() {
            return false;
        }
        current = path.parent();
    }
    true
}
