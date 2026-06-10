// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Helper functions for keystore operations

use crate::io::keystore::active::load_active_kid;
use crate::io::keystore::member::select_most_recent_kid;
use crate::io::keystore::storage::list_kids;
use crate::support::kid::format_kid_display_lossy;
use crate::support::kid::resolve_unique_kid;
use crate::{Error, ErrorKind, Result};
use std::path::Path;

pub fn resolve_member_kid_query(
    keystore_root: &Path,
    member_handle: &str,
    kid_query: &str,
) -> Result<String> {
    let kids = list_kids(keystore_root, member_handle)?;
    resolve_unique_kid(kids.iter().map(String::as_str), kid_query).map_err(|error| {
        if error.kind() == ErrorKind::NotFound {
            return Error::build_not_found_error(format!(
                "Specified kid '{}' not found for member '{}'",
                format_kid_display_lossy(kid_query),
                member_handle
            ));
        }
        error
    })
}

/// Resolves the kid to use for a given member_handle
///
/// Resolution order:
/// 1. If `kid_override` is provided, use it
/// 2. If an active kid is set, use it
/// 3. Otherwise, use the latest (most recent) kid
///
/// # Arguments
/// * `keystore_root` - Path to the keystore root directory
/// * `member_handle` - The member handle to resolve the kid for
/// * `kid_override` - Optional explicit kid to use (bypasses active/latest selection)
///
/// # Returns
/// The resolved kid as a String
///
/// # Errors
/// - `Error::NotFound` if no keys found for the member_handle
/// - `Error::NotFound` if kid_override is provided but doesn't exist
pub fn resolve_kid(
    keystore_root: &Path,
    member_handle: &str,
    kid_override: Option<&str>,
) -> Result<String> {
    if let Some(kid) = kid_override {
        return resolve_member_kid_query(keystore_root, member_handle, kid);
    }

    if let Some(active_kid) = load_active_kid(member_handle, keystore_root)? {
        return Ok(active_kid);
    }

    select_most_recent_kid(keystore_root, member_handle)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/keystore_helpers_test.rs"]
mod keystore_helpers_test;
