// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Read-only queries over workspace member files, both active and incoming.
//! Verifies each member document and collects per-entry warnings instead of failing the whole listing.

use crate::feature::member::verification::{
    derive_member_handle_from_path, verify_member_public_key_file,
};
use crate::io::workspace::members::{open_member_documents_at, MemberDocuments, MemberStatus};
use crate::model::identity::MemberHandle;
use crate::service::workspace::WorkspaceAccess;
use crate::support::path::format_path_relative_to_cwd;
use crate::Error;
use crate::Result;

use super::types::{MemberListResult, MemberShowResult, MembershipStatus};
use super::view::{build_member_document_view, build_member_list_entry};

pub fn list_members(workspace: &WorkspaceAccess) -> Result<MemberListResult> {
    let mut warnings = Vec::new();
    Ok(MemberListResult {
        active: collect_member_entries(
            &open_member_documents_at(workspace.directory(), MemberStatus::Active)?,
            &mut warnings,
        )?,
        incoming: collect_member_entries(
            &open_member_documents_at(workspace.directory(), MemberStatus::Incoming)?,
            &mut warnings,
        )?,
        warnings,
    })
}

pub fn load_member_show_result(
    workspace: &WorkspaceAccess,
    member_handle: &str,
) -> Result<MemberShowResult> {
    // The handle becomes one entry name below members/, so it is validated as a
    // handle before it is joined onto the directory rather than after.
    let member_handle = MemberHandle::try_from(member_handle)?;
    let member_handle = member_handle.as_str();
    let name = format!("{member_handle}.json");
    for status in [MemberStatus::Active, MemberStatus::Incoming] {
        let documents = open_member_documents_at(workspace.directory(), status)?;
        if documents.names().contains(&name) {
            let public_key = documents.load(&name)?;
            let source_name = format_path_relative_to_cwd(&documents.document_path(&name));
            let verified =
                verify_member_public_key_file(&public_key, Some(member_handle), &source_name)?;
            return Ok(MemberShowResult {
                member: build_member_document_view(verified.public_key, verified.warnings)?,
                status: MembershipStatus::from(status),
            });
        }
    }
    Err(Error::build_not_found_error(format!(
        "Member '{member_handle}' not found in workspace"
    )))
}

fn collect_member_entries(
    documents: &MemberDocuments,
    warnings: &mut Vec<String>,
) -> Result<Vec<super::types::MemberListEntry>> {
    let mut entries = Vec::new();
    for name in documents.names() {
        let member_path = documents.document_path(name);
        let source_name = format_path_relative_to_cwd(&member_path);
        let expected_member_handle = derive_member_handle_from_path(&member_path);
        let result = documents.load(name).and_then(|public_key| {
            verify_member_public_key_file(&public_key, Some(&expected_member_handle), &source_name)
        });
        match result {
            Ok(verified) => entries.push(build_member_list_entry(verified.public_key)?),
            Err(error) => warnings.push(format!(
                "Skipping invalid member file {}: {}",
                format_path_relative_to_cwd(&member_path),
                error
            )),
        }
    }
    Ok(entries)
}
