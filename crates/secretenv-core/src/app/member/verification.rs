// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::require_workspace;
use crate::feature::member::verification::verify_member;
use crate::support::runtime::block_on_result;
use crate::Result;

use super::types::MemberVerificationResult;
use super::view::build_member_verification_result;

pub fn verify_members(
    options: &CommonCommandOptions,
    member_handles: &[String],
    verbose: bool,
) -> Result<Vec<MemberVerificationResult>> {
    let workspace = require_workspace(options, "member verify")?;
    let results = block_on_result(verify_member(&workspace.root_path, member_handles, verbose))?;
    Ok(results
        .into_iter()
        .map(build_member_verification_result)
        .collect())
}
