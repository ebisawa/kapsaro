// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::app::context::options::CommonCommandOptions;
use crate::config::types::SshSigningMethod;

pub(crate) fn build_test_command_options(
    home: &Path,
    workspace: Option<&Path>,
) -> CommonCommandOptions {
    build_test_command_options_with(home, workspace, None, false, None)
}

pub(crate) fn build_test_signing_command_options(
    home: &Path,
    workspace: &Path,
) -> CommonCommandOptions {
    CommonCommandOptions {
        home: Some(home.to_path_buf()),
        identity: Some(home.join(".ssh").join("test_ed25519")),
        verbose: false,
        workspace: Some(workspace.to_path_buf()),
        ssh_signing_method: Some(SshSigningMethod::SshKeygen),
    }
}

fn build_test_command_options_with(
    home: &Path,
    workspace: Option<&Path>,
    identity: Option<&Path>,
    verbose: bool,
    ssh_signing_method: Option<SshSigningMethod>,
) -> CommonCommandOptions {
    CommonCommandOptions {
        home: Some(home.to_path_buf()),
        identity: identity.map(Path::to_path_buf),
        verbose,
        workspace: workspace.map(Path::to_path_buf),
        ssh_signing_method,
    }
}
