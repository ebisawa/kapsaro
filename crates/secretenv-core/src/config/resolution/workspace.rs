// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace setting precedence and global config lookup.
//!
//! The full resolution order is CLI, environment, global config, auto-detect.

use crate::config::types::ConfigKey;
use crate::io::workspace::detection::{
    resolve_optional_workspace, resolve_workspace, WorkspaceRoot,
};
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

use super::common::{expand_tilde, load_field_from_global_config};

const ENV_WORKSPACE: &str = "SECRETENV_WORKSPACE";

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
    base_dir: Option<&Path>,
) -> Result<Option<WorkspaceResolution>> {
    resolve_optional_workspace_from_sources_with_base_resolver(workspace_opt, || {
        Ok(base_dir.map(Path::to_path_buf))
    })
}

pub(crate) fn resolve_optional_workspace_from_sources_with_base_resolver<F>(
    workspace_opt: Option<PathBuf>,
    resolve_base_dir: F,
) -> Result<Option<WorkspaceResolution>>
where
    F: FnOnce() -> Result<Option<PathBuf>>,
{
    if let Some(path_resolution) =
        resolve_workspace_path_from_sources_with_base_resolver(workspace_opt, resolve_base_dir)?
    {
        return resolve_workspace_from_path(path_resolution.path, path_resolution.source).map(Some);
    }

    resolve_optional_workspace(None).map(|workspace| {
        workspace.map(|root| WorkspaceResolution {
            root,
            source: WorkspaceSource::AutoDetect,
        })
    })
}

pub(crate) fn resolve_workspace_from_sources(
    workspace_opt: Option<PathBuf>,
    base_dir: Option<&Path>,
) -> Result<WorkspaceResolution> {
    resolve_optional_workspace_from_sources(workspace_opt, base_dir)?
        .ok_or_else(build_workspace_required_error)
}

pub(crate) fn resolve_workspace_path_from_sources(
    workspace_opt: Option<PathBuf>,
    base_dir: Option<&Path>,
) -> Result<Option<WorkspacePathResolution>> {
    resolve_workspace_path_from_sources_with_base_resolver(workspace_opt, || {
        Ok(base_dir.map(Path::to_path_buf))
    })
}

fn resolve_workspace_path_from_sources_with_base_resolver<F>(
    workspace_opt: Option<PathBuf>,
    resolve_base_dir: F,
) -> Result<Option<WorkspacePathResolution>>
where
    F: FnOnce() -> Result<Option<PathBuf>>,
{
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

    let base_dir = resolve_base_dir()?;
    if let Some(path) = resolve_workspace_from_config_base(base_dir.as_deref())? {
        return Ok(Some(WorkspacePathResolution {
            path,
            source: WorkspaceSource::GlobalConfig,
        }));
    }

    Ok(None)
}

pub(crate) fn resolve_workspace_from_config() -> Result<Option<PathBuf>> {
    resolve_workspace_from_config_base(None)
}

/// Resolve workspace path from global config.toml.
///
/// Reads the `workspace` key from the selected base directory config. Returns
/// `None` if not configured. Tilde (`~`) in the path is expanded to the HOME
/// directory.
pub(crate) fn resolve_workspace_from_config_base(
    base_dir: Option<&std::path::Path>,
) -> Result<Option<PathBuf>> {
    let value = load_field_from_global_config(ConfigKey::Workspace.canonical_name(), base_dir)?;
    match value {
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

fn build_workspace_required_error() -> Error {
    Error::build_config_error(
        "Workspace is required. Specify it with --workspace, SECRETENV_WORKSPACE, or config.toml workspace"
            .to_string(),
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/config_resolution_workspace_test.rs"]
mod tests;
