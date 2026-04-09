// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::require_workspace;
use crate::feature::member::add::add_member_from_file;
use crate::io::workspace::members::delete_member;
use crate::{Error, Result};

use super::types::MemberRemoveResult;

pub fn add_member(options: &CommonCommandOptions, filename: &Path, force: bool) -> Result<String> {
    let workspace = require_workspace(options, "member add")?;
    add_member_from_file(&workspace.root_path, filename, force)
}

pub fn remove_member(
    options: &CommonCommandOptions,
    member_id: &str,
    force: bool,
) -> Result<MemberRemoveResult> {
    if !force {
        return Err(Error::Config {
            message: format!(
                "Removing member '{}' requires --force flag. This will affect secrets shared with this member.",
                member_id
            ),
        });
    }

    let workspace = require_workspace(options, "member remove")?;
    delete_member(&workspace.root_path, member_id)?;
    Ok(MemberRemoveResult {
        member_id: member_id.to_string(),
    })
}
