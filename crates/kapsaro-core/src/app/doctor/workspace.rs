// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use crate::app::context::options::CommonCommandOptions;
use crate::config::resolution::workspace::{
    resolve_optional_workspace_from_sources, resolve_workspace_path_from_sources,
};
use crate::io::config::paths::get_global_config_path_from_base;
use crate::io::keystore::resolver::KeystoreResolver;
use crate::io::workspace::detection::WorkspaceRoot;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};

use super::types::{DoctorCategory, DoctorCheck, DoctorSubject};

use crate::support::fs::policy::is_real_dir;

pub struct DoctorWorkspaceState {
    pub workspace_root: Option<WorkspaceRoot>,
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
}

pub fn check_workspace(options: &CommonCommandOptions) -> Result<DoctorWorkspaceState> {
    let base_dir = options.resolve_base_dir()?;
    let keystore_root = KeystoreResolver::resolve(options.home.as_ref())?;
    let config_path = get_global_config_path_from_base(&base_dir);
    let mut checks = vec![build_workspace_paths_check(
        &base_dir,
        &keystore_root,
        &config_path,
    )];

    let resolved = resolve_doctor_workspace(options, &base_dir)?;
    let Some((workspace_root, source)) = resolved else {
        checks.push(check_unresolved_workspace());
        return Ok(build_workspace_state(None, false, checks));
    };

    checks.push(check_resolved_workspace(&workspace_root, source));
    let structure_ok = workspace_structure_ok(&workspace_root.root_path);
    checks.push(check_workspace_structure(
        &workspace_root.root_path,
        structure_ok,
    ));
    checks.extend(check_gitless_workspace(&workspace_root.root_path));

    Ok(build_workspace_state(
        Some(workspace_root),
        structure_ok,
        checks,
    ))
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
    structure_ok: bool,
    checks: Vec<DoctorCheck>,
) -> DoctorWorkspaceState {
    DoctorWorkspaceState {
        workspace_root,
        structure_ok,
        checks,
    }
}

fn resolve_doctor_workspace(
    options: &CommonCommandOptions,
    base_dir: &Path,
) -> Result<Option<(WorkspaceRoot, &'static str)>> {
    if let Some(path_resolution) =
        resolve_workspace_path_from_sources(options.workspace.clone(), Some(base_dir))?
    {
        let workspace = canonicalize_doctor_workspace(path_resolution.path)?;
        return Ok(Some((workspace, path_resolution.source.as_str())));
    }

    resolve_optional_workspace_from_sources(options.workspace.clone(), Some(base_dir)).map(
        |resolution| {
            resolution.map(|workspace| {
                let source = workspace.source.as_str();
                (workspace.root, source)
            })
        },
    )
}

fn canonicalize_doctor_workspace(path: PathBuf) -> Result<WorkspaceRoot> {
    let root_path = path.canonicalize().map_err(|error| {
        Error::build_config_error(format!(
            "Invalid workspace path '{}': {}",
            format_path_relative_to_cwd(&path),
            error
        ))
    })?;
    Ok(WorkspaceRoot { root_path })
}

fn workspace_structure_ok(workspace_root: &Path) -> bool {
    let required = required_workspace_dirs(workspace_root);
    required.iter().all(|path| is_real_dir(path))
}

fn check_workspace_structure(workspace_root: &Path, structure_ok: bool) -> DoctorCheck {
    let required = required_workspace_dirs(workspace_root);
    let missing = required
        .iter()
        .filter(|path| !is_real_dir(path))
        .map(|path| format_path_relative_to_cwd(path))
        .collect::<Vec<_>>();
    if structure_ok {
        return DoctorCheck::ok(
            "workspace.structure",
            DoctorCategory::Workspace,
            DoctorSubject::Path(format_path_relative_to_cwd(workspace_root)),
            "Workspace has members/active, members/incoming, and secrets",
        );
    }
    DoctorCheck::fail_with_reason_and_next_action(
        "workspace.structure",
        DoctorCategory::Workspace,
        DoctorSubject::Path(format_path_relative_to_cwd(workspace_root)),
        "Workspace is missing required directories",
        format!("missing: {}", missing.join(", ")),
        "run kapsaro init or repair the workspace",
    )
}

fn required_workspace_dirs(workspace_root: &Path) -> [PathBuf; 3] {
    [
        workspace_root.join("members/active"),
        workspace_root.join("members/incoming"),
        workspace_root.join("secrets"),
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
