// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Explicit paths and operation controls used by workspace tests.
//! Keeps test fixture inputs independent from production CLI resolution types.

use std::path::{Path, PathBuf};

use kapsaro_core::api::operation::OperationOptions;
use kapsaro_core::test_support::settings::types::SshSigningMethod;
use kapsaro_core::{Error, Result};

#[derive(Debug, Clone, Default)]
pub struct TestCommandOptions {
    pub home: Option<PathBuf>,
    pub identity: Option<PathBuf>,
    pub workspace: Option<PathBuf>,
    pub allow_expired_key: bool,
    pub ssh_signing_method: Option<SshSigningMethod>,
}

impl TestCommandOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_home(mut self, home: Option<PathBuf>) -> Self {
        self.home = home;
        self
    }

    pub fn with_identity(mut self, identity: Option<PathBuf>) -> Self {
        self.identity = identity;
        self
    }

    pub fn with_workspace(mut self, workspace: Option<PathBuf>) -> Self {
        self.workspace = workspace;
        self
    }

    pub fn with_ssh_signing_method(mut self, method: Option<SshSigningMethod>) -> Self {
        self.ssh_signing_method = method;
        self
    }

    pub fn resolve_base_dir(&self) -> Result<PathBuf> {
        self.home
            .clone()
            .ok_or_else(|| Error::build_config_error("test home is required"))
    }

    pub fn resolve_keystore_root(&self) -> Result<PathBuf> {
        self.resolve_base_dir().map(|base| base.join("keys"))
    }

    pub fn operation_options(&self) -> OperationOptions {
        OperationOptions::new().with_allow_expired_key(self.allow_expired_key)
    }
}

pub fn build_test_command_options(home: &Path, workspace: Option<&Path>) -> TestCommandOptions {
    build_test_command_options_with(home, workspace, None, false, None)
}

pub fn build_test_signing_command_options(home: &Path, workspace: &Path) -> TestCommandOptions {
    build_test_command_options_with(
        home,
        Some(workspace),
        Some(&home.join(".ssh").join("test_ed25519")),
        false,
        Some(SshSigningMethod::SshKeygen),
    )
}

pub fn build_test_command_options_with(
    home: &Path,
    workspace: Option<&Path>,
    identity: Option<&Path>,
    _verbose: bool,
    ssh_signing_method: Option<SshSigningMethod>,
) -> TestCommandOptions {
    TestCommandOptions::new()
        .with_home(Some(home.to_path_buf()))
        .with_identity(identity.map(Path::to_path_buf))
        .with_workspace(workspace.map(Path::to_path_buf))
        .with_ssh_signing_method(ssh_signing_method)
}
