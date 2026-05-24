// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! member verify command orchestration.
//! Resolves workspace member targets before delegating verification logic.

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::require_workspace;
use crate::feature::member::verification::verify_member_files;
use crate::io::workspace::members::{get_active_member_file_path, list_active_member_paths};
use crate::support::display::sanitize_display_field;
use crate::support::runtime::block_on;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

use super::types::MemberVerificationResult;
use super::view::build_member_verification_result;

pub fn verify_members(
    options: &CommonCommandOptions,
    member_handles: &[String],
    verbose: bool,
) -> Result<Vec<MemberVerificationResult>> {
    let workspace = require_workspace(options, "member verify")?;
    let member_files = select_verification_member_files(&workspace.root_path, member_handles)?;
    let results = block_on(verify_member_files(&member_files, verbose))?;
    Ok(results
        .into_iter()
        .map(build_member_verification_result)
        .collect())
}

fn select_verification_member_files(
    workspace_path: &Path,
    member_handles: &[String],
) -> Result<Vec<PathBuf>> {
    if member_handles.is_empty() {
        return list_active_member_paths(workspace_path);
    }

    member_handles
        .iter()
        .map(|member_handle| {
            let path = get_active_member_file_path(workspace_path, member_handle);
            path.exists().then_some(path).ok_or_else(|| {
                Error::build_not_found_error(format!(
                    "Member '{}' not found in active/",
                    sanitize_display_field(member_handle)
                ))
            })
        })
        .collect()
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_member_verification_test.rs"]
mod tests;
