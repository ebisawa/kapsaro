// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Keystore storage operations for key documents
//!
//! Save and load PrivateKey and PublicKey.

use crate::format::schema::document::{parse_private_key_str, parse_public_key_str};
use crate::io::document_store::{
    CollectPermissionWarnings, DocumentStore, FailOnPermissionWarning,
};
use crate::model::private_key::PrivateKey;
use crate::model::public_key::PublicKey;
use crate::support::fs::{ensure_dir_restricted, list_dir};
use crate::support::kid::format_kid_display_lossy;
use crate::support::kid::resolve_unique_kid;
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};

// ============================================================================
// Path Helpers
// ============================================================================

/// Build the key directory path
fn key_dir(keystore_root: &Path, member_handle: &str, kid: &str) -> PathBuf {
    keystore_root.join(member_handle).join(kid)
}

/// Write key pair files to a temporary directory, cleaning up on failure.
fn save_key_pair_to_tmp(
    tmp_dir: &Path,
    private_key: &PrivateKey,
    public_key: &PublicKey,
) -> Result<()> {
    let result: Result<()> = (|| {
        DocumentStore::<FailOnPermissionWarning>::save_json_restricted(
            &tmp_dir.join("private.json"),
            private_key,
        )?;
        DocumentStore::<CollectPermissionWarnings>::save_json_restricted(
            &tmp_dir.join("public.json"),
            public_key,
        )?;
        Ok(())
    })();

    if let Err(e) = result {
        let _ = fs::remove_dir_all(tmp_dir);
        return Err(e);
    }

    Ok(())
}

/// Save a key pair atomically.
///
/// 1. Create a temporary directory `<member_handle>/.tmp-<uuid>/`
/// 2. Write `private.json` and `public.json`
/// 3. Rename to `<member_handle>/<kid>/`
///    The destination directory is either complete or absent.
pub fn save_key_pair_atomic(
    keystore_root: &Path,
    member_handle: &str,
    kid: &str,
    private_key: &PrivateKey,
    public_key: &PublicKey,
) -> Result<()> {
    let member_dir = keystore_root.join(member_handle);
    ensure_dir_restricted(&member_dir)?;

    let tmp_name = format!(".tmp-{}", uuid::Uuid::new_v4());
    let tmp_dir = member_dir.join(&tmp_name);
    ensure_dir_restricted(&tmp_dir)?;

    save_key_pair_to_tmp(&tmp_dir, private_key, public_key)?;

    let final_dir = member_dir.join(kid);
    fs::rename(&tmp_dir, &final_dir).map_err(|e| {
        Error::build_io_error_with_source(
            format!(
                "Failed to rename {} to {}: {}",
                format_path_relative_to_cwd(&tmp_dir),
                format_path_relative_to_cwd(&final_dir),
                e
            ),
            e,
        )
    })?;

    Ok(())
}

/// Load PrivateKey from keystore
pub fn load_private_key(
    keystore_root: &Path,
    member_handle: &str,
    kid: &str,
) -> Result<PrivateKey> {
    let path = key_dir(keystore_root, member_handle, kid).join("private.json");
    DocumentStore::<FailOnPermissionWarning>::load_required(
        &path,
        keystore_root,
        MAX_JSON_DOCUMENT_READ_SIZE,
        "PrivateKey file",
        |content| parse_private_key_document(content, &path),
    )
    .map(|loaded| loaded.document)
}

/// Load PublicKey from keystore
pub fn load_public_key(keystore_root: &Path, member_handle: &str, kid: &str) -> Result<PublicKey> {
    let path = key_dir(keystore_root, member_handle, kid).join("public.json");
    let loaded = DocumentStore::<CollectPermissionWarnings>::load_required(
        &path,
        keystore_root,
        MAX_JSON_DOCUMENT_READ_SIZE,
        "PublicKey file",
        |content| parse_public_key_document(content, &path),
    )?;
    for warning in loaded.permission_warnings {
        tracing::warn!("{}", warning);
    }
    Ok(loaded.document)
}

fn parse_private_key_document(content: &str, path: &Path) -> Result<PrivateKey> {
    let source_name = format_path_relative_to_cwd(path);
    parse_private_key_str(content, &source_name)
}

fn parse_public_key_document(content: &str, path: &Path) -> Result<PublicKey> {
    let source_name = format_path_relative_to_cwd(path);
    parse_public_key_str(content, &source_name)
}

/// List directory names in a path, filtering by predicate
///
/// Returns sorted list of directory names that pass the filter.
fn list_directories(path: &Path, filter: impl Fn(&str) -> bool) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let entries = list_dir(path)?;

    let mut names: Vec<String> = entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let dir_path = entry.path();
            if dir_path.is_dir() {
                let name = dir_path.file_name()?.to_str()?;
                if filter(name) {
                    return Some(name.to_string());
                }
            }
            None
        })
        .collect();

    names.sort();
    Ok(names)
}

/// List all key IDs for a member
///
/// Returns canonical key IDs sorted lexicographically.
pub fn list_kids(keystore_root: &Path, member_handle: &str) -> Result<Vec<String>> {
    let member_path = keystore_root.join(member_handle);
    list_directories(
        &member_path,
        |name| name != "active", // Skip "active" file
    )
}

/// List all member handles in the keystore
///
/// Returns member handles sorted lexicographically.
pub fn list_member_handles(keystore_root: &Path) -> Result<Vec<String>> {
    list_directories(keystore_root, |_| true)
}

/// Find member_handle by kid (scanning all members in keystore)
///
/// Scans all members in the keystore and returns the member_handle that owns
/// the given kid directory. Since key directory names use canonical `kid`, at most
/// one member will match.
pub fn find_member_by_kid(keystore_root: &Path, kid: &str) -> Result<String> {
    let member_handles = list_member_handles(keystore_root)?;
    let candidates = member_handles
        .iter()
        .map(|member_handle| {
            list_kids(keystore_root, member_handle).map(|kids| (member_handle, kids))
        })
        .collect::<Result<Vec<_>>>()?;
    let candidate_kids = candidates
        .iter()
        .flat_map(|(_, kids)| kids.iter().map(String::as_str))
        .collect::<Vec<_>>();
    let resolved_kid = resolve_unique_kid(candidate_kids, kid)?;

    for (member_handle, kids) in candidates {
        if kids.iter().any(|candidate| candidate == &resolved_kid) {
            return Ok(member_handle.clone());
        }
    }

    Err(Error::NotFound {
        message: format!(
            "kid '{}' not found in keystore",
            format_kid_display_lossy(kid)
        ),
    })
}
