// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use crate::app::context::options::CommonCommandOptions;
use crate::config::resolution::workspace::resolve_optional_workspace_from_sources;
use crate::io::workspace::detection::WorkspaceRoot;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use tracing::debug;

/// Resolve the workspace if one is explicitly configured or auto-detectable.
pub fn load_optional_workspace(options: &CommonCommandOptions) -> Result<Option<WorkspaceRoot>> {
    load_optional_workspace_with_base(options, None)
}

fn load_optional_workspace_with_base(
    options: &CommonCommandOptions,
    base_dir: Option<&Path>,
) -> Result<Option<WorkspaceRoot>> {
    resolve_optional_workspace_from_sources(options.workspace.clone(), base_dir)
        .map(|resolution| resolution.map(|workspace| workspace.root))
}

/// Resolve a workspace and fail if none is configured or auto-detectable.
pub fn require_workspace(options: &CommonCommandOptions, purpose: &str) -> Result<WorkspaceRoot> {
    load_optional_workspace(options)?
        .ok_or_else(|| Error::build_config_error(format!("Workspace is required for {}", purpose)))
}

#[derive(Debug, Clone)]
pub struct CommandPathResolution {
    pub base_dir: PathBuf,
    pub keystore_root: PathBuf,
    pub workspace_root: Option<WorkspaceRoot>,
}

impl CommandPathResolution {
    pub fn load(options: &CommonCommandOptions) -> Result<Self> {
        let base_dir = options.resolve_base_dir()?;
        let keystore_root = options.resolve_keystore_root()?;
        let workspace_root = load_optional_workspace_with_base(options, Some(&base_dir))?;
        let paths = Self {
            base_dir,
            keystore_root,
            workspace_root,
        };
        log_path_resolution(options, &paths);
        Ok(paths)
    }

    pub fn require_workspace(options: &CommonCommandOptions, purpose: &str) -> Result<Self> {
        let paths = Self::load(options)?;
        if paths.workspace_root.is_none() {
            return Err(Error::build_config_error(format!(
                "Workspace is required for {}",
                purpose
            )));
        }
        Ok(paths)
    }

    pub fn into_required_workspace_root(self) -> WorkspaceRoot {
        self.workspace_root
            .expect("required workspace resolution must contain a workspace root")
    }
}

fn log_path_resolution(options: &CommonCommandOptions, paths: &CommandPathResolution) {
    if !options.debug {
        return;
    }
    let workspace = paths
        .workspace_root
        .as_ref()
        .map(|root| format_path_relative_to_cwd(&root.root_path))
        .unwrap_or_else(|| "(none)".to_string());
    debug!(
        "[CTX] paths: base_dir={}, keystore_root={}, workspace_root={}",
        format_path_relative_to_cwd(&paths.base_dir),
        format_path_relative_to_cwd(&paths.keystore_root),
        workspace
    );
}
