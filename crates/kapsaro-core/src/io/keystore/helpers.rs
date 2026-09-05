// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Helper functions for keystore operations.
//! Resolves typed key and member identifiers through an anchored keystore capability.

use crate::io::keystore::access::KeystoreAccess;
use crate::model::identity::{Kid, MemberHandle};
use crate::support::kid::{format_kid_display_lossy, resolve_unique_kid};
use crate::{Error, ErrorKind, Result};

pub(crate) fn resolve_member_kid_query(
    access: &KeystoreAccess,
    member_handle: &MemberHandle,
    kid_query: &str,
) -> Result<Kid> {
    access
        .resolve_kid(member_handle, Some(kid_query))
        .map_err(|error| {
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

/// Find the member that owns a kid by scanning every member in the keystore.
///
/// Key directory names use the canonical `kid`, so at most one member matches.
///
/// Internal staging names are skipped while each member's published key names
/// are enumerated.
pub(crate) fn find_member_by_kid(access: &KeystoreAccess, kid: &str) -> Result<MemberHandle> {
    let member_handles = access.list_members()?;
    let candidates = member_handles
        .iter()
        .map(|member_handle| {
            access
                .list_kids(member_handle)
                .map(|kids| (member_handle, kids))
        })
        .collect::<Result<Vec<_>>>()?;
    let candidate_kids = candidates
        .iter()
        .flat_map(|(_, kids)| kids.iter().map(Kid::as_str))
        .collect::<Vec<_>>();
    let resolved_kid = resolve_unique_kid(candidate_kids, kid)?;
    candidates
        .into_iter()
        .find(|(_, kids)| {
            kids.iter()
                .any(|candidate| candidate.as_str() == resolved_kid)
        })
        .map(|(member_handle, _)| member_handle.clone())
        .ok_or_else(|| {
            Error::build_not_found_error(format!(
                "kid '{}' not found in keystore",
                format_kid_display_lossy(kid)
            ))
        })
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_keystore_helpers_test.rs"]
mod io_keystore_helpers_test;
