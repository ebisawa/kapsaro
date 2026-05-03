// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::require_workspace;
use crate::feature::member::verification::verify_member_file;
use crate::io::workspace::members::{
    get_active_member_file_path, get_incoming_member_file_path, list_active_member_paths,
    list_incoming_member_paths, MemberStatus,
};
use crate::support::path::format_path_relative_to_cwd;
use crate::Error;
use crate::Result;

use super::types::{MemberListResult, MemberShowResult, MembershipStatus};
use super::view::{build_member_document_view, build_member_list_entry};

pub fn list_members(options: &CommonCommandOptions) -> Result<MemberListResult> {
    let workspace = require_workspace(options, "member list")?;
    let mut warnings = Vec::new();
    Ok(MemberListResult {
        active: collect_member_entries(
            &list_active_member_paths(&workspace.root_path)?,
            options.verbose,
            &mut warnings,
        )?,
        incoming: collect_member_entries(
            &list_incoming_member_paths(&workspace.root_path)?,
            options.verbose,
            &mut warnings,
        )?,
        warnings,
    })
}

pub fn load_member_show_result(
    options: &CommonCommandOptions,
    member_handle: &str,
) -> Result<MemberShowResult> {
    let workspace = require_workspace(options, "member show")?;
    let active_path = get_active_member_file_path(&workspace.root_path, member_handle);
    let incoming_path = get_incoming_member_file_path(&workspace.root_path, member_handle);
    let (member_path, status) = if active_path.exists() {
        (active_path, MemberStatus::Active)
    } else if incoming_path.exists() {
        (incoming_path, MemberStatus::Incoming)
    } else {
        return Err(Error::NotFound {
            message: format!("Member '{}' not found in workspace", member_handle),
        });
    };
    let verified = verify_member_file(&member_path, Some(member_handle), options.verbose)?;
    Ok(MemberShowResult {
        member: build_member_document_view(verified.public_key, verified.warnings)?,
        status: MembershipStatus::from(status),
    })
}

fn collect_member_entries(
    member_paths: &[std::path::PathBuf],
    debug: bool,
    warnings: &mut Vec<String>,
) -> Result<Vec<super::types::MemberListEntry>> {
    let mut entries = Vec::new();
    for member_path in member_paths {
        match verify_member_file(member_path, None, debug) {
            Ok(verified) => entries.push(build_member_list_entry(verified.public_key)?),
            Err(error) => warnings.push(format!(
                "Skipping invalid member file {}: {}",
                format_path_relative_to_cwd(member_path),
                error
            )),
        }
    }
    Ok(entries)
}
