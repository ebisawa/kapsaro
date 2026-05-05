// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Active key management

use crate::io::document_store::{CollectPermissionWarnings, DocumentStore};
use crate::support::kid::normalize_kid;
use crate::support::limits::MAX_ACTIVE_KID_FILE_SIZE;
use crate::Error;
use std::fs;
use std::path::Path;

const ACTIVE_FILE_SUBJECT: &str = "active key file";

/// Load the active kid for a member.
///
/// Returns the canonical serialized `kid`, or None if no active key is set.
pub fn load_active_kid(member_handle: &str, keystore_root: &Path) -> Result<Option<String>, Error> {
    let active_path = keystore_root.join(member_handle).join("active");

    let Some(loaded) = DocumentStore::<CollectPermissionWarnings>::load_optional(
        &active_path,
        keystore_root,
        MAX_ACTIVE_KID_FILE_SIZE,
        ACTIVE_FILE_SUBJECT,
        parse_active_kid,
    )?
    else {
        return Ok(None);
    };
    for warning in loaded.permission_warnings {
        tracing::warn!("{}", warning);
    }
    Ok(loaded.document)
}

/// Set the active kid for a member.
///
/// Creates or updates the active file with the canonical serialized `kid`.
pub fn set_active_kid(member_handle: &str, kid: &str, keystore_root: &Path) -> Result<(), Error> {
    let canonical_kid = normalize_kid(kid)?;
    let active_path = keystore_root.join(member_handle).join("active");

    // Write kid to active file atomically (with trailing newline)
    DocumentStore::<CollectPermissionWarnings>::save_text_restricted(
        &active_path,
        &format!("{}\n", canonical_kid),
    )
}

/// Clear the active kid for a member
///
/// Removes the active file
pub fn clear_active_kid(member_handle: &str, keystore_root: &Path) -> Result<(), Error> {
    let active_path = keystore_root.join(member_handle).join("active");

    if active_path.exists() {
        fs::remove_file(&active_path).map_err(|e| {
            Error::build_io_error_with_source(format!("Failed to remove active file: {}", e), e)
        })?;
    }

    Ok(())
}

fn parse_active_kid(content: &str) -> Result<Option<String>, Error> {
    let kid = content.trim();
    if kid.is_empty() {
        return Ok(None);
    }
    Ok(Some(normalize_kid(kid)?))
}
