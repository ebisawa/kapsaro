// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::search::{detect_workspace_root, find_git_root, validate_workspace_path, WorkspaceRoot};
use crate::config::resolution::workspace::resolve_workspace_from_config;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::env;
use std::path::PathBuf;

pub fn resolve_workspace(workspace_opt: Option<PathBuf>) -> Result<WorkspaceRoot> {
    if let Some(path) = workspace_opt {
        let canonical = path.canonicalize().map_err(|e| Error::Config {
            message: format!(
                "Invalid workspace path '{}': {}",
                format_path_relative_to_cwd(&path),
                e
            ),
        })?;
        return validate_workspace_path(&canonical);
    }

    if let Ok(env_path) = env::var("SECRETENV_WORKSPACE") {
        let path = PathBuf::from(env_path);
        let canonical = path.canonicalize().map_err(|e| Error::Config {
            message: format!(
                "Invalid SECRETENV_WORKSPACE path '{}': {}",
                format_path_relative_to_cwd(&path),
                e
            ),
        })?;
        return validate_workspace_path(&canonical);
    }

    if let Some(config_path) = resolve_workspace_from_config()? {
        let canonical = config_path.canonicalize().map_err(|e| Error::Config {
            message: format!(
                "Invalid workspace path in config.toml '{}': {}",
                format_path_relative_to_cwd(&config_path),
                e
            ),
        })?;
        return validate_workspace_path(&canonical);
    }

    let current_dir = env::current_dir().map_err(|e| Error::Config {
        message: format!("Failed to get current directory: {}", e),
    })?;
    detect_workspace_root(&current_dir)
}

pub fn resolve_optional_workspace(workspace_opt: Option<PathBuf>) -> Result<Option<WorkspaceRoot>> {
    if let Some(path) = workspace_opt {
        return resolve_workspace(Some(path)).map(Some);
    }

    if env::var("SECRETENV_WORKSPACE").is_ok() {
        return resolve_workspace(None).map(Some);
    }

    if resolve_workspace_from_config()?.is_some() {
        return resolve_workspace(None).map(Some);
    }

    match env::current_dir() {
        Ok(current_dir) => match detect_workspace_root(&current_dir) {
            Ok(workspace) => Ok(Some(workspace)),
            Err(Error::NotFound { .. }) => Ok(None),
            Err(error) => Err(error),
        },
        Err(e) => Err(Error::Config {
            message: format!("Failed to get current directory: {}", e),
        }),
    }
}

pub fn resolve_workspace_creation_path(workspace_opt: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = workspace_opt {
        return Ok(path);
    }

    let current_dir = env::current_dir().map_err(|e| {
        Error::build_io_error_with_source(format!("Failed to get current directory: {}", e), e)
    })?;

    find_git_root(&current_dir).map(|root| root.join(".secretenv")).ok_or_else(|| Error::Config {
        message:
            "No git repository found. Specify workspace explicitly with --workspace or SECRETENV_WORKSPACE."
                .to_string(),
    })
}
