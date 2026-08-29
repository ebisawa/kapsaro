// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Resolution of the directories a command works against.
//! Turns common options into a base directory, keystore root, and workspace.

use std::path::PathBuf;

use crate::app::context::options::CommonCommandOptions;
use crate::config::resolution::global::GlobalConfigSnapshot;
use crate::config::resolution::workspace::resolve_optional_workspace_from_sources;
use crate::io::workspace::detection::WorkspaceRoot;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use tracing::debug;

/// Resolve the workspace if one is explicitly configured or auto-detectable.
pub fn load_optional_workspace(options: &CommonCommandOptions) -> Result<Option<WorkspaceRoot>> {
    load_optional_workspace_with_config(options, options.global_config()?)
}

fn load_optional_workspace_with_config(
    options: &CommonCommandOptions,
    config: &GlobalConfigSnapshot,
) -> Result<Option<WorkspaceRoot>> {
    resolve_optional_workspace_from_sources(options.workspace.clone(), config)
        .map(|resolution| resolution.map(|workspace| workspace.root))
}

/// Resolve a workspace and fail if none is configured or auto-detectable.
pub fn require_workspace(options: &CommonCommandOptions, purpose: &str) -> Result<WorkspaceRoot> {
    load_optional_workspace(options)?.ok_or_else(|| build_workspace_not_found_error(purpose))
}

pub(crate) fn build_workspace_not_found_error(purpose: &str) -> Error {
    Error::build_config_error(format!(
        "workspace not found.\n\
         Reason: {purpose} requires a Kapsaro workspace, but no workspace could be resolved.\n\
         Options:\n\
         1. Run kapsaro init to create a new workspace in the current Git repository\n\
         2. Run inside a Git repository that contains .kapsaro/\n\
         3. Configure an existing workspace explicitly with --workspace <path>"
    ))
}

#[derive(Debug, Clone)]
pub struct CommandPathResolution {
    pub base_dir: PathBuf,
    pub keystore_root: PathBuf,
    pub workspace_root: Option<WorkspaceRoot>,
    /// Local state root every later step of this command works through.
    ///
    /// The configuration, the keystore and the trust store all live under one
    /// root, so the root the options fixed is taken over here and handed down.
    /// Each of them resolving the same path again would let a root repointed
    /// mid-command answer one question from one tree and the next from another.
    home: Option<AnchoredDir>,
    /// Configuration every later step of this command resolves settings from.
    ///
    /// The workspace, the member handle and the whole SSH signing environment
    /// are all configured in one file, so it is read once through the fixed
    /// root and handed down rather than opened again by each of them.
    pub(crate) global_config: GlobalConfigSnapshot,
}

impl CommandPathResolution {
    pub fn load(options: &CommonCommandOptions) -> Result<Self> {
        let base_dir = options.resolve_base_dir()?;
        let keystore_root = options.resolve_keystore_root()?;
        let home = options.fixed_home()?.cloned();
        let global_config = options.global_config()?.clone();
        let workspace_root = load_optional_workspace_with_config(options, &global_config)?;
        let paths = Self {
            base_dir,
            keystore_root,
            workspace_root,
            home,
            global_config,
        };
        log_path_resolution(&paths);
        Ok(paths)
    }

    /// The local state root this command fixed, when there is one.
    pub(crate) fn home(&self) -> Option<&AnchoredDir> {
        self.home.as_ref()
    }

    pub fn require_workspace(options: &CommonCommandOptions, purpose: &str) -> Result<Self> {
        let paths = Self::load(options)?;
        if paths.workspace_root.is_none() {
            return Err(build_workspace_not_found_error(purpose));
        }
        Ok(paths)
    }

    pub fn into_required_workspace_root(self) -> WorkspaceRoot {
        self.workspace_root
            .expect("required workspace resolution must contain a workspace root")
    }
}

fn log_path_resolution(paths: &CommandPathResolution) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
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

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_context_paths_test.rs"]
mod app_context_paths_test;
