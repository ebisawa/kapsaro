// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::super::paths::{
    ensure_members_dir, get_active_member_file_path, get_incoming_member_file_path, MemberStatus,
};
use super::uniqueness::ensure_member_document_kid_is_unique;
use crate::format::schema::document::parse_public_key_str;
use crate::support::fs::atomic;
use crate::{Error, Result};
use std::path::Path;

fn save_member_file(path: &Path, content: &str) -> Result<()> {
    atomic::save_text(path, content)
}

pub fn save_member_content(
    workspace_path: &Path,
    status: MemberStatus,
    member_handle: &str,
    content: &str,
    overwrite: bool,
) -> Result<()> {
    ensure_members_dir(workspace_path, status)?;
    let source_name = format!("member content for {}", member_handle);
    let public_key = parse_public_key_str(content, &source_name)?;
    let path = match status {
        MemberStatus::Active => get_active_member_file_path(workspace_path, member_handle),
        MemberStatus::Incoming => get_incoming_member_file_path(workspace_path, member_handle),
    };
    if !overwrite && path.exists() {
        return Err(Error::build_invalid_operation_error(format!(
            "Member '{}' already exists in {}/ (use --force to overwrite)",
            member_handle,
            member_status_dir_name(status)
        )));
    }
    ensure_member_document_kid_is_unique(
        workspace_path,
        status,
        member_handle,
        &public_key.protected.kid,
        overwrite && path.exists(),
    )?;
    save_member_file(&path, content)
}

pub(super) fn member_status_dir_name(status: MemberStatus) -> &'static str {
    match status {
        MemberStatus::Active => "active",
        MemberStatus::Incoming => "incoming",
    }
}
