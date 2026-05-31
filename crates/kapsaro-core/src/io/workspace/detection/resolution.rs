// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace path validation and auto-detection helpers.
//!
//! Higher-level setting precedence is resolved by config::resolution::workspace.

use super::search::{detect_workspace_root, find_git_root, validate_workspace_path, WorkspaceRoot};
use crate::support::fs::policy::is_real_dir;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, ErrorKind, Result};
use std::env;
use std::path::PathBuf;

pub fn resolve_workspace(workspace_opt: Option<PathBuf>) -> Result<WorkspaceRoot> {
    if let Some(path) = workspace_opt {
        return validate_explicit_workspace_path(path);
    }

    let current_dir = env::current_dir().map_err(|e| {
        Error::build_config_error(format!("Failed to get current directory: {}", e))
    })?;
    detect_workspace_root(&current_dir)
}

pub fn resolve_optional_workspace(workspace_opt: Option<PathBuf>) -> Result<Option<WorkspaceRoot>> {
    if let Some(path) = workspace_opt {
        return resolve_workspace(Some(path)).map(Some);
    }

    match env::current_dir() {
        Ok(current_dir) => match detect_workspace_root(&current_dir) {
            Ok(workspace) => Ok(Some(workspace)),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        },
        Err(e) => Err(Error::build_config_error(format!(
            "Failed to get current directory: {}",
            e
        ))),
    }
}

fn validate_explicit_workspace_path(path: PathBuf) -> Result<WorkspaceRoot> {
    let canonical = path.canonicalize().map_err(|e| {
        Error::build_config_error(format!(
            "Invalid workspace path '{}': {}",
            format_path_relative_to_cwd(&path),
            e
        ))
    })?;
    validate_workspace_path(&canonical)
}

pub fn resolve_workspace_creation_path(workspace_opt: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = workspace_opt {
        return Ok(path);
    }

    let current_dir = env::current_dir().map_err(|e| {
        Error::build_io_error_with_source(format!("Failed to get current directory: {}", e), e)
    })?;

    if let Some(root) = find_git_root(&current_dir) {
        return Ok(root.join(".kapsaro"));
    }

    let current_workspace = current_dir.join(".kapsaro");
    if is_real_dir(&current_workspace) {
        return current_workspace.canonicalize().map_err(|e| {
            Error::build_io_error_with_source(format!("Failed to canonicalize path: {}", e), e)
        });
    }

    Err(Error::build_config_error(
        "No git repository or current .kapsaro directory found".to_string(),
    ))
}
