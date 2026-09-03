// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace path validation for callers that already selected a path.
//! Returns canonical roots without consulting environment variables or configuration.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::io::workspace::detection::{
    detect_workspace_root, resolve_workspace, resolve_workspace_creation_path_from,
};
use crate::io::workspace::setup::SECRETS_DIR_NAME;
use crate::service::key::KeyContext;
use crate::service::trust::TrustCommandSession;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::{open_child_dir, DirectoryScope, OpenDir};
use crate::Result;

/// Opened workspace directories retained for one or more write plans.
pub struct WorkspaceWriteDirectories {
    workspace: AnchoredDir,
    secrets: Arc<OpenDir>,
}

impl WorkspaceWriteDirectories {
    /// Open an explicit workspace root and its secrets directory once.
    pub fn open(workspace_path: impl Into<PathBuf>) -> Result<Self> {
        let workspace = AnchoredDir::open(
            workspace_path.into(),
            DirectoryScope::Generic,
            "workspace root",
        )?;
        let secrets = Arc::new(open_child_dir(&workspace, SECRETS_DIR_NAME)?);
        Ok(Self { workspace, secrets })
    }
}

/// Fixed workspace, secrets, local-state, and signing capabilities for one write.
pub(crate) struct WorkspaceWriteCapabilities<'a> {
    directories: &'a WorkspaceWriteDirectories,
    trust: &'a TrustCommandSession,
}

impl<'a> WorkspaceWriteCapabilities<'a> {
    /// Bind opened workspace directories to the already fixed signing session.
    pub(crate) fn new(
        directories: &'a WorkspaceWriteDirectories,
        trust: &'a TrustCommandSession,
    ) -> Self {
        Self { directories, trust }
    }

    pub(crate) fn workspace(&self) -> &AnchoredDir {
        &self.directories.workspace
    }

    pub(crate) fn secrets(&self) -> &Arc<OpenDir> {
        &self.directories.secrets
    }

    pub(crate) fn trust(&self) -> &TrustCommandSession {
        self.trust
    }

    pub(crate) fn key_context(&self) -> &KeyContext {
        self.trust.key_ctx()
    }
}

/// Validate one caller-selected workspace and return its canonical root.
pub fn validate_workspace_path(path: &Path) -> Result<PathBuf> {
    resolve_workspace(Some(path.to_path_buf())).map(|workspace| workspace.root_path)
}

/// Detect a workspace starting at the caller-selected directory.
pub fn detect_workspace_path(start: &Path) -> Result<PathBuf> {
    detect_workspace_root(start).map(|workspace| workspace.root_path)
}

/// Select the workspace path a registration would create from an explicit start directory.
pub fn select_workspace_creation_path(start: &Path) -> Result<PathBuf> {
    resolve_workspace_creation_path_from(start)
}
