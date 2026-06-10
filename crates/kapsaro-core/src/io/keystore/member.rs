// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Keystore member-oriented lookup helpers.

use crate::io::keystore::active;
use crate::io::keystore::paths;
use crate::io::keystore::storage::{list_kids, load_public_key};
use crate::model::public_key::PublicKey;
use crate::support::fs::list_dir;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::path::Path;

/// Active key document lookup result.
pub struct ActiveKeyDocument {
    pub kid: String,
    pub public_key: PublicKey,
}

/// Load member_handle from keystore if exactly one exists.
pub fn load_single_member_handle_from_keystore(keystore_root: &Path) -> Result<Option<String>> {
    if !keystore_root.exists() {
        return Ok(None);
    }

    let member_dirs: Vec<String> = list_dir(keystore_root)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            if entry.path().is_dir() {
                entry.file_name().to_str().map(String::from)
            } else {
                None
            }
        })
        .collect();

    match member_dirs.len() {
        1 => Ok(Some(member_dirs[0].clone())),
        _ => Ok(None),
    }
}

/// Load the active public key document for a member when the private key still exists.
pub fn find_active_key_document(
    member_handle: &str,
    keystore_root: &Path,
) -> Result<Option<ActiveKeyDocument>> {
    let Some(kid) = active::load_active_kid(member_handle, keystore_root)? else {
        return Ok(None);
    };

    let private_key_path =
        paths::get_private_key_file_path_from_root(keystore_root, member_handle, &kid);
    if !private_key_path.exists() {
        active::clear_active_kid(member_handle, keystore_root)?;
        return Ok(None);
    }

    let public_key = load_public_key(keystore_root, member_handle, &kid)?;
    Ok(Some(ActiveKeyDocument { kid, public_key }))
}

/// Load all public key documents for a member from the local keystore.
pub fn load_public_keys_for_member(
    keystore_root: &Path,
    member_handle: &str,
) -> Result<Vec<PublicKey>> {
    let kids = list_kids(keystore_root, member_handle)?;
    kids.into_iter()
        .map(|kid| load_public_key(keystore_root, member_handle, &kid))
        .collect()
}

/// Select latest valid (non-expired) key for a member.
pub fn select_latest_valid_kid(keystore_root: &Path, member_handle: &str) -> Result<String> {
    let kids = list_kids(keystore_root, member_handle)?;
    if kids.is_empty() {
        return Err(Error::build_not_found_error(format!(
            "No keys found for member: {}",
            member_handle
        )));
    }

    let now = time::OffsetDateTime::now_utc();
    let mut candidates = Vec::new();
    for kid in kids {
        let public_key = load_public_key(keystore_root, member_handle, &kid)?;
        let expires_at = parse_expires_at(&public_key)?;
        let created_at = parse_created_at(&public_key)?;

        if now < expires_at {
            candidates.push((kid, created_at));
        }
    }

    if let Some((kid, _)) = select_preferred_kid(candidates) {
        return Ok(kid);
    }

    Err(Error::build_not_found_error(format!(
        "No valid (non-expired) keys found for member: {}",
        member_handle
    )))
}

/// Remove a key directory from the keystore.
pub fn remove_key_directory(keystore_root: &Path, member_handle: &str, kid: &str) -> Result<()> {
    let key_dir = keystore_root.join(member_handle).join(kid);
    std::fs::remove_dir_all(&key_dir).map_err(|e| {
        Error::build_io_error_with_source(
            format!(
                "Failed to remove key directory {}: {}",
                format_path_relative_to_cwd(&key_dir),
                e
            ),
            e,
        )
    })
}

/// Select the most recent key for a member based on `created_at desc, kid asc`.
pub fn select_most_recent_kid(keystore_root: &Path, member_handle: &str) -> Result<String> {
    let kids = list_kids(keystore_root, member_handle)?;
    if kids.is_empty() {
        return Err(Error::build_not_found_error(format!(
            "No keys found for member: {}",
            member_handle
        )));
    }

    let candidates = kids
        .into_iter()
        .map(|kid| {
            let public_key = load_public_key(keystore_root, member_handle, &kid)?;
            let created_at = parse_created_at(&public_key)?;
            Ok((kid, created_at))
        })
        .collect::<Result<Vec<_>>>()?;

    select_preferred_kid(candidates)
        .map(|(kid, _)| kid)
        .ok_or_else(|| {
            Error::build_config_error(
                "Internal error: key candidate list became empty after validation".to_string(),
            )
        })
}

fn parse_created_at(public_key: &PublicKey) -> Result<time::OffsetDateTime> {
    let created_at = public_key.protected.created_at.as_deref().ok_or_else(|| {
        Error::build_parse_error(format!(
            "Missing created_at for key: {}",
            public_key.protected.kid
        ))
    })?;

    time::OffsetDateTime::parse(created_at, &time::format_description::well_known::Rfc3339).map_err(
        |e| {
            Error::build_parse_error_with_source(
                format!(
                    "Invalid created_at format for key {}: {}",
                    public_key.protected.kid, e
                ),
                e,
            )
        },
    )
}

fn parse_expires_at(public_key: &PublicKey) -> Result<time::OffsetDateTime> {
    time::OffsetDateTime::parse(
        &public_key.protected.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|e| {
        Error::build_parse_error_with_source(
            format!(
                "Invalid expires_at format for key {}: {}",
                public_key.protected.kid, e
            ),
            e,
        )
    })
}

fn select_preferred_kid(
    mut candidates: Vec<(String, time::OffsetDateTime)>,
) -> Option<(String, time::OffsetDateTime)> {
    candidates.sort_by(|(kid_a, created_at_a), (kid_b, created_at_b)| {
        created_at_b
            .cmp(created_at_a)
            .then_with(|| kid_a.cmp(kid_b))
    });
    candidates.into_iter().next()
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_keystore_member_test.rs"]
mod io_keystore_member_test;
