// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use secretenv_core::cli_api::test_support::storage::workspace::detection::WorkspaceRoot;

pub(crate) fn build_test_workspace_root(workspace: &Path) -> WorkspaceRoot {
    WorkspaceRoot {
        root_path: workspace.to_path_buf(),
        has_marker_file: false,
        has_config_file: false,
    }
}
