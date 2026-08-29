// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace setting precedence and global config lookup.
//!
//! The full resolution order is CLI, environment, global config, auto-detect.

use crate::config::resolution::global::GlobalConfigSnapshot;
use crate::config::types::ConfigKey;
use crate::io::workspace::detection::{
    resolve_optional_workspace, resolve_workspace, WorkspaceRoot,
};
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

use super::common::expand_tilde;

const ENV_WORKSPACE: &str = "KAPSARO_WORKSPACE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkspaceSource {
    CommandLine,
    Environment,
    GlobalConfig,
    AutoDetect,
}

impl WorkspaceSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::CommandLine => "command line",
            Self::Environment => ENV_WORKSPACE,
            Self::GlobalConfig => "config.toml",
            Self::AutoDetect => "auto-detect",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct WorkspaceResolution {
    pub(crate) root: WorkspaceRoot,
    pub(crate) source: WorkspaceSource,
}

#[derive(Debug, Clone)]
pub(crate) struct WorkspacePathResolution {
    pub(crate) path: PathBuf,
    pub(crate) source: WorkspaceSource,
}

pub(crate) fn resolve_optional_workspace_from_sources(
    workspace_opt: Option<PathBuf>,
    config: &GlobalConfigSnapshot,
) -> Result<Option<WorkspaceResolution>> {
    if let Some(path_resolution) = resolve_workspace_path_from_sources(workspace_opt, config)? {
        return resolve_workspace_from_path(path_resolution.path, path_resolution.source).map(Some);
    }

    resolve_optional_workspace(None).map(|workspace| {
        workspace.map(|root| WorkspaceResolution {
            root,
            source: WorkspaceSource::AutoDetect,
        })
    })
}

pub(crate) fn resolve_workspace_path_from_sources(
    workspace_opt: Option<PathBuf>,
    config: &GlobalConfigSnapshot,
) -> Result<Option<WorkspacePathResolution>> {
    if let Some(path) = workspace_opt {
        return Ok(Some(WorkspacePathResolution {
            path,
            source: WorkspaceSource::CommandLine,
        }));
    }

    if let Some(path) = load_workspace_from_env()? {
        return Ok(Some(WorkspacePathResolution {
            path,
            source: WorkspaceSource::Environment,
        }));
    }

    if let Some(path) = resolve_workspace_from_config_base(config)? {
        return Ok(Some(WorkspacePathResolution {
            path,
            source: WorkspaceSource::GlobalConfig,
        }));
    }

    Ok(None)
}

/// Resolve workspace path from global config.toml.
///
/// Reads the `workspace` key from the command's configuration. Returns `None`
/// if not configured. Tilde (`~`) in the path is expanded to the HOME directory.
pub(crate) fn resolve_workspace_from_config_base(
    config: &GlobalConfigSnapshot,
) -> Result<Option<PathBuf>> {
    match config.get(ConfigKey::Workspace.canonical_name())? {
        Some(path_str) => {
            let expanded = expand_tilde(&path_str)?;
            Ok(Some(expanded))
        }
        None => Ok(None),
    }
}

fn load_workspace_from_env() -> Result<Option<PathBuf>> {
    match std::env::var(ENV_WORKSPACE) {
        Ok(path) => Ok(Some(PathBuf::from(path))),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(Error::build_config_error(format!(
            "{} environment variable contains invalid UTF-8",
            ENV_WORKSPACE
        ))),
    }
}

fn resolve_workspace_from_path(
    path: PathBuf,
    source: WorkspaceSource,
) -> Result<WorkspaceResolution> {
    resolve_workspace(Some(path.clone()))
        .map(|root| WorkspaceResolution { root, source })
        .map_err(|error| build_workspace_source_error(source, &path, error))
}

fn build_workspace_source_error(source: WorkspaceSource, path: &Path, error: Error) -> Error {
    match source {
        WorkspaceSource::CommandLine => error,
        WorkspaceSource::Environment => Error::build_config_error(format!(
            "Invalid {} path '{}': {}",
            ENV_WORKSPACE,
            format_path_relative_to_cwd(path),
            error
        )),
        WorkspaceSource::GlobalConfig => Error::build_config_error(format!(
            "Invalid workspace path in config.toml '{}': {}",
            format_path_relative_to_cwd(path),
            error
        )),
        WorkspaceSource::AutoDetect => error,
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/config_resolution_workspace_test.rs"]
mod tests;
