// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use tempfile::TempDir;

use crate::app::context::execution::{resolve_write_execution, ExecutionContext};
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::{resolve_ssh_context_by_active_key, ResolvedSshSigningContext};
use crate::test_utils::member_id as test_member_id;
use crate::test_utils::setup_member_key_context;

use super::context_paths::build_test_workspace_root;

pub(crate) fn build_test_execution_context(
    home: &TempDir,
    member_id: &str,
    workspace: Option<&Path>,
) -> ExecutionContext {
    ExecutionContext {
        member_id: test_member_id(member_id),
        key_ctx: setup_member_key_context(home, member_id, None),
        workspace_root: workspace.map(build_test_workspace_root),
    }
}

pub(crate) fn resolve_test_write_execution(
    options: &CommonCommandOptions,
    member_id: &str,
) -> ExecutionContext {
    let ssh_ctx = Some(resolve_test_ssh_context(options, member_id));
    resolve_write_execution(options, Some(member_id.to_string()), ssh_ctx).unwrap()
}

pub(crate) fn resolve_test_ssh_context(
    options: &CommonCommandOptions,
    member_id: &str,
) -> ResolvedSshSigningContext {
    resolve_ssh_context_by_active_key(options, Some(member_id.to_string())).unwrap()
}
