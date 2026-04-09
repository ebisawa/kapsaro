// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::super::paths::{
    active_member_file_path, ensure_members_dir, incoming_member_file_path, MemberStatus,
};
use super::uniqueness::ensure_member_document_kid_is_unique;
use crate::format::schema::document::parse_public_key_str;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use std::fs;
use std::path::Path;

fn save_member_file(path: &Path, content: &str) -> Result<()> {
    fs::write(path, content).map_err(|e| {
        Error::io_with_source(
            format!(
                "Failed to write {}: {}",
                display_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })
}

pub fn save_member_content(
    workspace_path: &Path,
    status: MemberStatus,
    member_id: &str,
    content: &str,
    overwrite: bool,
) -> Result<()> {
    ensure_members_dir(workspace_path, status)?;
    let source_name = format!("member content for {}", member_id);
    let public_key = parse_public_key_str(content, &source_name)?;
    let path = match status {
        MemberStatus::Active => active_member_file_path(workspace_path, member_id),
        MemberStatus::Incoming => incoming_member_file_path(workspace_path, member_id),
    };
    if !overwrite && path.exists() {
        return Err(Error::InvalidOperation {
            message: format!(
                "Member '{}' already exists in {}/ (use --force to overwrite)",
                member_id,
                member_status_dir_name(status)
            ),
        });
    }
    ensure_member_document_kid_is_unique(
        workspace_path,
        status,
        member_id,
        &public_key.protected.kid,
        overwrite && path.exists(),
    )?;
    save_member_file(&path, content)
}

pub fn delete_member(workspace_path: &Path, member_id: &str) -> Result<()> {
    let active_path = active_member_file_path(workspace_path, member_id);
    if !active_path.exists() {
        return Err(Error::NotFound {
            message: format!("Member '{}' not found in active/", member_id),
        });
    }

    fs::remove_file(&active_path).map_err(|e| {
        Error::io_with_source(format!("Failed to delete member '{}': {}", member_id, e), e)
    })?;

    Ok(())
}

pub(super) fn member_status_dir_name(status: MemberStatus) -> &'static str {
    match status {
        MemberStatus::Active => "active",
        MemberStatus::Incoming => "incoming",
    }
}
