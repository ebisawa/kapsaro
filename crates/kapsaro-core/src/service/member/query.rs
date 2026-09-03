// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Read-only queries over workspace member files, both active and incoming.
//! Verifies each member document and collects per-entry warnings instead of failing the whole listing.

use crate::feature::member::verification::{
    derive_member_handle_from_path, verify_member_public_key_file,
};
use crate::io::workspace::members::{
    get_active_member_file_path, get_incoming_member_file_path, list_active_member_paths,
    list_incoming_member_paths, load_member_file_from_path, MemberStatus,
};
use crate::support::path::format_path_relative_to_cwd;
use crate::Error;
use crate::Result;

use super::types::{MemberListResult, MemberShowResult, MembershipStatus};
use super::view::{build_member_document_view, build_member_list_entry};

pub fn list_members(workspace_path: &std::path::Path) -> Result<MemberListResult> {
    let mut warnings = Vec::new();
    Ok(MemberListResult {
        active: collect_member_entries(&list_active_member_paths(workspace_path)?, &mut warnings)?,
        incoming: collect_member_entries(
            &list_incoming_member_paths(workspace_path)?,
            &mut warnings,
        )?,
        warnings,
    })
}

pub fn load_member_show_result(
    workspace_path: &std::path::Path,
    member_handle: &str,
) -> Result<MemberShowResult> {
    let active_path = get_active_member_file_path(workspace_path, member_handle);
    let incoming_path = get_incoming_member_file_path(workspace_path, member_handle);
    let (member_path, status) = if active_path.exists() {
        (active_path, MemberStatus::Active)
    } else if incoming_path.exists() {
        (incoming_path, MemberStatus::Incoming)
    } else {
        return Err(Error::build_not_found_error(format!(
            "Member '{}' not found in workspace",
            member_handle
        )));
    };
    let public_key = load_member_file_from_path(&member_path)?;
    let source_name = format_path_relative_to_cwd(&member_path);
    let verified = verify_member_public_key_file(&public_key, Some(member_handle), &source_name)?;
    Ok(MemberShowResult {
        member: build_member_document_view(verified.public_key, verified.warnings)?,
        status: MembershipStatus::from(status),
    })
}

fn collect_member_entries(
    member_paths: &[std::path::PathBuf],
    warnings: &mut Vec<String>,
) -> Result<Vec<super::types::MemberListEntry>> {
    let mut entries = Vec::new();
    for member_path in member_paths {
        let source_name = format_path_relative_to_cwd(member_path);
        let expected_member_handle = derive_member_handle_from_path(member_path);
        let result = load_member_file_from_path(member_path).and_then(|public_key| {
            verify_member_public_key_file(&public_key, Some(&expected_member_handle), &source_name)
        });
        match result {
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
