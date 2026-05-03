// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Member add feature - add external public key to incoming.

use super::verification::verify_member_file;
use crate::format::schema::document::parse_public_key_str;
use crate::io::workspace::members::{save_member_content, MemberStatus};
use crate::support::fs::load_text_with_limit;
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
use crate::support::path::format_path_relative_to_cwd;
use crate::Result;
use std::path::Path;

/// Add a member's public key file to members/incoming/.
///
/// Reads the file, validates it as a PublicKey JSON, and saves to incoming.
/// Returns the member_handle extracted from the public key.
pub fn add_member_from_file(
    workspace_path: &Path,
    file_path: &Path,
    force: bool,
) -> Result<String> {
    let content = load_text_with_limit(file_path, MAX_JSON_DOCUMENT_READ_SIZE, "PublicKey file")?;

    let public_key = parse_public_key_str(&content, &format_path_relative_to_cwd(file_path))?;
    verify_member_file(file_path, Some(&public_key.protected.subject_handle), false)?;

    let member_handle = public_key.protected.subject_handle.clone();

    save_member_content(
        workspace_path,
        MemberStatus::Incoming,
        &member_handle,
        &content,
        force,
    )?;

    Ok(member_handle)
}
