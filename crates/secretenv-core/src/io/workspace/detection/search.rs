// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::support::fs::policy::is_real_dir;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Workspace root information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRoot {
    /// Absolute path to workspace root
    pub root_path: PathBuf,
    /// True if .secretenv-root marker file exists
    pub has_marker_file: bool,
    /// True if config.toml exists
    pub has_config_file: bool,
}

impl WorkspaceRoot {
    pub fn members_dir(&self) -> PathBuf {
        self.root_path.join("members")
    }

    pub fn secrets_dir(&self) -> PathBuf {
        self.root_path.join("secrets")
    }

    pub fn config_path(&self) -> Option<PathBuf> {
        if self.has_config_file {
            Some(self.root_path.join("config.toml"))
        } else {
            None
        }
    }
}

pub(super) fn validate_workspace_path(path: &Path) -> Result<WorkspaceRoot> {
    if let Some(workspace) = check_explicit_workspace_dir(path) {
        Ok(workspace)
    } else {
        Err(Error::build_not_found_error(format!(
            "Path '{}' is not a valid workspace (missing members/ or secrets/ directories)",
            format_path_relative_to_cwd(path)
        )))
    }
}

pub fn detect_workspace_root(start_path: &Path) -> Result<WorkspaceRoot> {
    let mut current = start_path.canonicalize().map_err(|e| {
        Error::build_io_error_with_source(format!("Failed to canonicalize path: {}", e), e)
    })?;
    let Some(git_root) = find_git_root(&current) else {
        return detect_current_workspace_without_git(start_path, &current);
    };

    loop {
        if let Some(workspace) = check_workspace(&current) {
            return Ok(workspace);
        }

        if current.join(".secretenv-root").exists() {
            return Err(Error::build_not_found_error(format!(
                "Found .secretenv-root marker at '{}' but missing members/ or secrets/ directories",
                format_path_relative_to_cwd(&current)
            )));
        }

        if current == git_root {
            // In a git worktree, .git is a file. Resolve the main repository
            // root and search there as well.
            if let Some(main_root) = resolve_worktree_main_root(&git_root) {
                if let Some(workspace) = check_workspace(&main_root) {
                    return Ok(workspace);
                }
            }
            return Err(Error::build_not_found_error(format!(
                "No workspace found within git repository (searched from '{}')",
                format_path_relative_to_cwd(start_path)
            )));
        }

        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => {
                return Err(Error::build_not_found_error(format!(
                    "No workspace found: searched from '{}' to filesystem root",
                    format_path_relative_to_cwd(start_path)
                )))
            }
        }
    }
}

fn detect_current_workspace_without_git(
    start_path: &Path,
    current: &Path,
) -> Result<WorkspaceRoot> {
    if let Some(workspace) = check_workspace(current) {
        return Ok(workspace);
    }

    if current.join(".secretenv").exists() {
        return Err(Error::build_not_found_error(format!(
            "Found .secretenv at '{}' but missing members/ or secrets/ directories",
            format_path_relative_to_cwd(current)
        )));
    }

    Err(Error::build_not_found_error(format!(
            "No workspace found from '{}'. Specify workspace explicitly with --workspace or SECRETENV_WORKSPACE.",
            format_path_relative_to_cwd(start_path)
        )))
}

pub(super) fn find_git_root(start: &Path) -> Option<PathBuf> {
    let mut current = start.canonicalize().ok()?;
    loop {
        if current.join(".git").exists() {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Resolve the main repository root from a git worktree.
///
/// In a worktree, `.git` is a file containing `gitdir: <path>`.
/// The referenced directory contains a `commondir` file pointing to the
/// main repository's `.git` directory.
fn resolve_worktree_main_root(worktree_root: &Path) -> Option<PathBuf> {
    let dot_git = worktree_root.join(".git");
    if !dot_git.is_file() {
        return None;
    }

    let content = fs::read_to_string(&dot_git)
        .map_err(|e| tracing::debug!("Failed to read .git file at {}: {}", dot_git.display(), e))
        .ok()?;
    let gitdir = content.strip_prefix("gitdir: ")?.trim();
    let gitdir_path = Path::new(gitdir);
    let gitdir_abs = if gitdir_path.is_absolute() {
        gitdir_path.to_path_buf()
    } else {
        worktree_root.join(gitdir_path)
    };

    let commondir_file = gitdir_abs.join("commondir");
    let commondir_content = fs::read_to_string(&commondir_file)
        .map_err(|e| {
            tracing::debug!(
                "Failed to read commondir at {}: {}",
                commondir_file.display(),
                e
            )
        })
        .ok()?;
    let commondir = commondir_content.trim();
    let commondir_path = Path::new(commondir);
    let main_git_dir = if commondir_path.is_absolute() {
        commondir_path.to_path_buf()
    } else {
        gitdir_abs.join(commondir_path)
    };

    main_git_dir
        .canonicalize()
        .map_err(|e| {
            tracing::debug!(
                "Failed to canonicalize main git dir {}: {}",
                main_git_dir.display(),
                e
            )
        })
        .ok()?
        .parent()
        .map(Path::to_path_buf)
}

fn check_explicit_workspace_dir(path: &Path) -> Option<WorkspaceRoot> {
    validate_workspace_structure(path)
}

fn check_workspace(path: &Path) -> Option<WorkspaceRoot> {
    let secretenv_dir = path.join(".secretenv");
    if is_real_dir(&secretenv_dir) {
        validate_workspace_structure(&secretenv_dir)
    } else {
        None
    }
}

fn validate_workspace_structure(path: &Path) -> Option<WorkspaceRoot> {
    let members_dir = path.join("members");
    let members_active = members_dir.join("active");
    let secrets_dir = path.join("secrets");
    if is_real_dir(&members_dir) && is_real_dir(&members_active) && is_real_dir(&secrets_dir) {
        Some(WorkspaceRoot {
            root_path: path.to_path_buf(),
            has_marker_file: path.join(".secretenv-root").exists(),
            has_config_file: path.join("config.toml").exists(),
        })
    } else {
        None
    }
}
