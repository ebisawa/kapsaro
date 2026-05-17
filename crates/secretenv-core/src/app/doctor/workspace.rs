// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::Path;

use crate::app::context::options::CommonCommandOptions;
use crate::io::config::paths::get_global_config_path_from_base;
use crate::io::keystore::resolver::KeystoreResolver;
use crate::io::workspace::detection::{resolve_optional_workspace_with_base, WorkspaceRoot};
use crate::support::path::format_path_relative_to_cwd;
use crate::Result;

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
    let mut checks = vec![DoctorCheck::ok(
        "config.paths",
        DoctorCategory::Workspace,
        DoctorSubject::Path(format_path_relative_to_cwd(&base_dir)),
        format!(
            "Home: {}; keystore: {}; config: {}",
            format_path_relative_to_cwd(&base_dir),
            format_path_relative_to_cwd(&keystore_root),
            format_path_relative_to_cwd(&config_path)
        ),
    )];

    let resolved = resolve_doctor_workspace(options, &base_dir);
    let Some((workspace_root, source)) = resolved else {
        checks.push(
            DoctorCheck::fail(
                "workspace.resolve",
                DoctorCategory::Workspace,
                DoctorSubject::General("workspace".to_string()),
                "Workspace could not be resolved",
            )
            .with_next_action("specify --workspace or run from a workspace root"),
        );
        return Ok(DoctorWorkspaceState {
            workspace_root: None,
            structure_ok: false,
            checks,
        });
    };

    checks.push(DoctorCheck::ok(
        "workspace.resolve",
        DoctorCategory::Workspace,
        DoctorSubject::Path(format_path_relative_to_cwd(&workspace_root.root_path)),
        format!("Workspace resolved from {}", source),
    ));
    let structure_ok = workspace_structure_ok(&workspace_root.root_path);
    checks.push(check_workspace_structure(
        &workspace_root.root_path,
        structure_ok,
    ));
    if is_gitless_layout(&workspace_root.root_path) {
        checks.push(
            DoctorCheck::warn(
                "workspace.gitless",
                DoctorCategory::Workspace,
                DoctorSubject::Path(format_path_relative_to_cwd(&workspace_root.root_path)),
                "Workspace is not inside a git checkout",
            )
            .with_next_action("confirm this production layout is intentional"),
        );
    }

    Ok(DoctorWorkspaceState {
        workspace_root: Some(workspace_root),
        structure_ok,
        checks,
    })
}

fn resolve_doctor_workspace(
    options: &CommonCommandOptions,
    base_dir: &Path,
) -> Option<(WorkspaceRoot, &'static str)> {
    if let Some(path) = options.workspace.as_ref() {
        return Some((workspace_from_path(path), "command line"));
    }

    if let Ok(path) = env::var("SECRETENV_WORKSPACE") {
        return Some((workspace_from_path(Path::new(&path)), "SECRETENV_WORKSPACE"));
    }

    if let Ok(Some(path)) =
        crate::config::resolution::workspace::resolve_workspace_from_config_base(Some(base_dir))
    {
        return Some((workspace_from_path(&path), "config.toml"));
    }

    resolve_optional_workspace_with_base(None, Some(base_dir))
        .ok()
        .flatten()
        .map(|workspace| (workspace, "auto-detect"))
}

fn workspace_from_path(path: &Path) -> WorkspaceRoot {
    let root_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    WorkspaceRoot {
        has_marker_file: root_path.join(".secretenv-root").exists(),
        has_config_file: root_path.join("config.toml").exists(),
        root_path,
    }
}

fn workspace_structure_ok(workspace_root: &Path) -> bool {
    let required = [
        workspace_root.join("members/active"),
        workspace_root.join("members/incoming"),
        workspace_root.join("secrets"),
    ];
    required.iter().all(|path| is_real_dir(path))
}

fn check_workspace_structure(workspace_root: &Path, structure_ok: bool) -> DoctorCheck {
    let required = [
        workspace_root.join("members/active"),
        workspace_root.join("members/incoming"),
        workspace_root.join("secrets"),
    ];
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
    DoctorCheck::fail(
        "workspace.structure",
        DoctorCategory::Workspace,
        DoctorSubject::Path(format_path_relative_to_cwd(workspace_root)),
        "Workspace is missing required directories",
    )
    .with_reason(format!("missing: {}", missing.join(", ")))
    .with_next_action("run secretenv init or repair the workspace")
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
