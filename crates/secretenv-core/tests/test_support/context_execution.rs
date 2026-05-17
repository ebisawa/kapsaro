// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use tempfile::TempDir;

use crate::test_utils::member_handle as test_member_handle;
use crate::test_utils::setup_member_key_context;
use secretenv_core::cli_api::app::context::execution::{resolve_write_execution, ExecutionContext};
use secretenv_core::cli_api::app::context::options::CommonCommandOptions;
use secretenv_core::cli_api::app::context::ssh::{
    resolve_ssh_context_by_active_key, SshSigningContextResolution,
};

use super::context_paths::build_test_workspace_root;

pub(crate) fn build_test_execution_context(
    home: &TempDir,
    member_handle: &str,
    workspace: Option<&Path>,
) -> ExecutionContext {
    ExecutionContext {
        member_handle: test_member_handle(member_handle),
        key_ctx: setup_member_key_context(home, member_handle, None),
        workspace_root: workspace.map(build_test_workspace_root),
    }
}

pub(crate) fn resolve_test_write_execution(
    options: &CommonCommandOptions,
    member_handle: &str,
) -> ExecutionContext {
    let ssh_ctx = Some(resolve_test_ssh_context(options, member_handle));
    resolve_write_execution(options, Some(member_handle.to_string()), ssh_ctx).unwrap()
}

pub(crate) fn resolve_test_ssh_context(
    options: &CommonCommandOptions,
    member_handle: &str,
) -> SshSigningContextResolution {
    resolve_ssh_context_by_active_key(options, Some(member_handle.to_string())).unwrap()
}
