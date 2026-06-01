// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use kapsaro_core::cli_api::app::context::options::CommonCommandOptions;
use kapsaro_core::cli_api::test_support::settings::types::SshSigningMethod;

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
        debug: false,
        verbose: false,
        workspace: Some(workspace.to_path_buf()),
        ssh_signing_method: Some(SshSigningMethod::SshKeygen),
        allow_expired_key: false,
        allow_non_member: false,
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
        debug: false,
        verbose,
        workspace: workspace.map(Path::to_path_buf),
        ssh_signing_method,
        allow_expired_key: false,
        allow_non_member: false,
    }
}
