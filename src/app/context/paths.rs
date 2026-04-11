// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use crate::app::context::options::CommonCommandOptions;
use crate::io::workspace::detection::{resolve_optional_workspace, WorkspaceRoot};
use crate::{Error, Result};

/// Resolve the workspace if one is explicitly configured or auto-detectable.
pub(crate) fn load_optional_workspace(
    options: &CommonCommandOptions,
) -> Result<Option<WorkspaceRoot>> {
    resolve_optional_workspace(options.workspace.clone())
}

/// Resolve a workspace and fail if none is configured or auto-detectable.
pub(crate) fn require_workspace(
    options: &CommonCommandOptions,
    purpose: &str,
) -> Result<WorkspaceRoot> {
    load_optional_workspace(options)?.ok_or_else(|| Error::Config {
        message: format!("Workspace is required for {}", purpose),
    })
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedCommandPaths {
    pub base_dir: PathBuf,
    pub keystore_root: PathBuf,
    pub workspace_root: Option<WorkspaceRoot>,
}

impl ResolvedCommandPaths {
    pub(crate) fn load(options: &CommonCommandOptions) -> Result<Self> {
        Ok(Self {
            base_dir: options.resolve_base_dir()?,
            keystore_root: options.resolve_keystore_root()?,
            workspace_root: load_optional_workspace(options)?,
        })
    }

    pub(crate) fn require_workspace(options: &CommonCommandOptions, purpose: &str) -> Result<Self> {
        let paths = Self::load(options)?;
        if paths.workspace_root.is_none() {
            return Err(Error::Config {
                message: format!("Workspace is required for {}", purpose),
            });
        }
        Ok(paths)
    }
}
