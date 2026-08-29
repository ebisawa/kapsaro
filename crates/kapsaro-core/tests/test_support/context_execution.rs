// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use tempfile::TempDir;

use crate::test_utils::member_handle as test_member_handle;
use crate::test_utils::setup_member_key_context;
use kapsaro_core::api::key::KeyContext;
use kapsaro_core::cli_api::app::context::execution::{resolve_write_execution, ExecutionContext};
use kapsaro_core::cli_api::app::context::options::CommonCommandOptions;

use super::context_paths::build_test_workspace_root;

pub(crate) fn build_test_execution_context(
    home: &TempDir,
    member_handle: &str,
    workspace: Option<&Path>,
) -> ExecutionContext {
    ExecutionContext::from_test_parts(
        test_member_handle(member_handle),
        KeyContext::from_inner(setup_member_key_context(home, member_handle, None)),
        workspace.map(build_test_workspace_root),
        Some(home.path().to_path_buf()),
    )
    .unwrap()
}

pub(crate) fn resolve_test_write_execution(
    options: &CommonCommandOptions,
    member_handle: &str,
) -> ExecutionContext {
    resolve_write_execution(options, Some(member_handle.to_string())).unwrap()
}
