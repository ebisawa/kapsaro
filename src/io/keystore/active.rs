// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Active key management

use crate::support::fs::{atomic, check_permission_chain, load_text_with_limit};
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

    if !active_path.exists() {
        return Ok(None);
    }

    for warning in check_permission_chain(&active_path, keystore_root) {
        tracing::warn!("{}", warning);
    }

    let content =
        load_text_with_limit(&active_path, MAX_ACTIVE_KID_FILE_SIZE, ACTIVE_FILE_SUBJECT)?;

    // Trim whitespace and newlines
    let kid = content.trim();

    if kid.is_empty() {
        return Ok(None);
    }

    Ok(Some(normalize_kid(kid)?))
}

/// Set the active kid for a member.
///
/// Creates or updates the active file with the canonical serialized `kid`.
pub fn set_active_kid(member_handle: &str, kid: &str, keystore_root: &Path) -> Result<(), Error> {
    let canonical_kid = normalize_kid(kid)?;
    let active_path = keystore_root.join(member_handle).join("active");

    // Write kid to active file atomically (with trailing newline)
    atomic::save_text_restricted(&active_path, &format!("{}\n", canonical_kid))
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
