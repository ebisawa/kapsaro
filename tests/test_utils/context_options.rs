// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use secretenv_core::cli_api::app::context::options::CommonCommandOptions;

pub(crate) fn build_test_command_options(
    home: &Path,
    workspace: Option<&Path>,
) -> CommonCommandOptions {
    CommonCommandOptions {
        home: Some(home.to_path_buf()),
        identity: None,
        debug: false,
        verbose: false,
        workspace: workspace.map(Path::to_path_buf),
        ssh_signing_method: None,
        allow_expired_key: false,
    }
}
