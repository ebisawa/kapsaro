// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace root search and validated workspace metadata.
//! Detects workspace layout only; config precedence is settled elsewhere.

use crate::io::workspace::members::{ACTIVE_DIR_NAME, MEMBERS_DIR_NAME};
use crate::io::workspace::setup::SECRETS_DIR_NAME;
use crate::support::fs::policy::is_real_dir;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Name of the directory a workspace stands in inside a checkout.
pub(super) const WORKSPACE_DIR_NAME: &str = ".kapsaro";

/// Workspace root information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRoot {
    /// Absolute path to workspace root
    pub root_path: PathBuf,
}

pub(super) fn validate_workspace_path(path: &Path) -> Result<WorkspaceRoot> {
    validate_workspace_structure(path)?.ok_or_else(|| {
        Error::build_not_found_error(format!(
            "Path '{}' is not a valid workspace (missing members/ or secrets/ directories)",
            format_path_relative_to_cwd(path)
        ))
    })
}

pub fn detect_workspace_root(start_path: &Path) -> Result<WorkspaceRoot> {
    let current = start_path.canonicalize().map_err(|e| {
        Error::build_io_error_with_source(format!("Failed to canonicalize path: {}", e), e)
    })?;
    let Some(git_root) = find_git_root(&current)? else {
        return detect_current_workspace_without_git(start_path, &current);
    };
    search_workspace_towards_git_root(start_path, current, &git_root)
}

/// Walk from the starting directory up to the git root, stopping at the first
/// level that holds a workspace.
fn search_workspace_towards_git_root(
    start_path: &Path,
    mut current: PathBuf,
    git_root: &Path,
) -> Result<WorkspaceRoot> {
    loop {
        if let Some(workspace) = check_workspace(&current)? {
            return Ok(workspace);
        }
        if current == git_root {
            return search_worktree_main_repository(start_path, git_root);
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

/// Search the main repository once the checkout itself holds no workspace.
///
/// In a git worktree `.git` is a file, and the workspace may live in the main
/// repository the file points at rather than in the worktree.
fn search_worktree_main_repository(start_path: &Path, git_root: &Path) -> Result<WorkspaceRoot> {
    if let Some(main_root) = resolve_worktree_main_root(git_root) {
        if let Some(workspace) = check_workspace(&main_root)? {
            return Ok(workspace);
        }
    }
    Err(Error::build_not_found_error(format!(
        "No workspace found within git repository (searched from '{}')",
        format_path_relative_to_cwd(start_path)
    )))
}

fn detect_current_workspace_without_git(
    start_path: &Path,
    current: &Path,
) -> Result<WorkspaceRoot> {
    if let Some(workspace) = check_workspace(current)? {
        return Ok(workspace);
    }

    if let Some(rejected) = build_rejected_workspace_dir_error(current) {
        return Err(rejected);
    }

    Err(Error::build_not_found_error(format!(
        "No workspace found from '{}'",
        format_path_relative_to_cwd(start_path)
    )))
}

/// Say why the `.kapsaro` entry standing here was not taken as a workspace.
///
/// The search refuses a link in that position rather than following it, so the
/// reason is the link and not the layout below it. Reporting missing directories
/// would send an operator looking for a structure that is already there. `None`
/// means nothing stands under that name at all.
fn build_rejected_workspace_dir_error(current: &Path) -> Option<Error> {
    let workspace_dir = current.join(WORKSPACE_DIR_NAME);
    let entry_type = fs::symlink_metadata(&workspace_dir).ok()?.file_type();
    if entry_type.is_symlink() {
        return Some(Error::build_invalid_operation_error(format!(
            "'{}' is a symlink; a workspace directory is not followed through one",
            format_path_relative_to_cwd(&workspace_dir)
        )));
    }
    if !entry_type.is_dir() {
        return Some(Error::build_not_found_error(format!(
            "'{}' is not a directory and holds no workspace",
            format_path_relative_to_cwd(&workspace_dir)
        )));
    }
    Some(Error::build_not_found_error(format!(
        "Found .kapsaro at '{}' but missing members/ or secrets/ directories",
        format_path_relative_to_cwd(current)
    )))
}

pub(super) fn find_git_root(start: &Path) -> Result<Option<PathBuf>> {
    let Ok(mut current) = start.canonicalize() else {
        return Ok(None);
    };
    loop {
        if has_git_entry(&current)? {
            return Ok(Some(current));
        }
        if !current.pop() {
            return Ok(None);
        }
    }
}

/// Whether a `.git` entry stands here, refusing to answer a denied lookup.
///
/// In a worktree `.git` is a file rather than a directory, so the entry counts
/// whatever type it has, as long as it resolves: a symlink pointing nowhere is
/// no repository. A lookup that could not be made is an error and not a
/// `false`: reading a refusal as "no repository stands here" would carry the
/// search up past that level and settle on whatever repository is above it.
fn has_git_entry(current: &Path) -> Result<bool> {
    let git_entry = current.join(".git");
    match fs::metadata(&git_entry) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::build_io_error_with_source(
            format!(
                "Failed to inspect {}: {}",
                format_path_relative_to_cwd(&git_entry),
                error
            ),
            error,
        )),
    }
}

/// Resolve the main repository root from a git worktree.
///
/// In a worktree, `.git` is a file containing `gitdir: <path>`.
/// The referenced directory contains a `commondir` file pointing to the
/// main repository's `.git` directory.
fn resolve_worktree_main_root(worktree_root: &Path) -> Option<PathBuf> {
    let gitdir = resolve_worktree_gitdir(worktree_root)?;
    let main_git_dir = resolve_common_git_dir(&gitdir)?;
    canonical_parent(&main_git_dir)
}

/// The private git directory a worktree's `.git` file points at.
fn resolve_worktree_gitdir(worktree_root: &Path) -> Option<PathBuf> {
    let dot_git = worktree_root.join(".git");
    if !dot_git.is_file() {
        return None;
    }
    let content = load_git_metadata(&dot_git, ".git file")?;
    let gitdir = content.strip_prefix("gitdir: ")?.trim();
    Some(resolve_against(worktree_root, Path::new(gitdir)))
}

/// The shared `.git` directory the worktree's private directory records.
fn resolve_common_git_dir(gitdir: &Path) -> Option<PathBuf> {
    let commondir_file = gitdir.join("commondir");
    let content = load_git_metadata(&commondir_file, "commondir")?;
    Some(resolve_against(gitdir, Path::new(content.trim())))
}

fn load_git_metadata(path: &Path, subject: &str) -> Option<String> {
    fs::read_to_string(path)
        .map_err(|e| tracing::debug!("Failed to read {} at {}: {}", subject, path.display(), e))
        .ok()
}

fn resolve_against(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn canonical_parent(path: &Path) -> Option<PathBuf> {
    path.canonicalize()
        .map_err(|e| {
            tracing::debug!(
                "Failed to canonicalize main git dir {}: {}",
                path.display(),
                e
            )
        })
        .ok()?
        .parent()
        .map(Path::to_path_buf)
}

fn check_workspace(path: &Path) -> Result<Option<WorkspaceRoot>> {
    let kapsaro_dir = path.join(WORKSPACE_DIR_NAME);
    if !is_real_dir(&kapsaro_dir)? {
        return Ok(None);
    }
    validate_workspace_structure(&kapsaro_dir)
}

fn validate_workspace_structure(path: &Path) -> Result<Option<WorkspaceRoot>> {
    let members_dir = path.join(MEMBERS_DIR_NAME);
    if !(is_real_dir(&members_dir)?
        && is_real_dir(&members_dir.join(ACTIVE_DIR_NAME))?
        && is_real_dir(&path.join(SECRETS_DIR_NAME))?)
    {
        return Ok(None);
    }
    Ok(Some(WorkspaceRoot {
        root_path: path.to_path_buf(),
    }))
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/io_workspace_detection_search_test.rs"]
mod io_workspace_detection_search_test;
