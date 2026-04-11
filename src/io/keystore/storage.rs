// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Keystore storage operations for key documents
//!
//! Save and load PrivateKey and PublicKey.

use crate::format::schema::document::{parse_private_key_file, parse_public_key_file};
use crate::model::private_key::PrivateKey;
use crate::model::public_key::PublicKey;
use crate::support::fs::{atomic, check_permission_chain, ensure_dir_restricted, list_dir};
use crate::support::kid::kid_display_lossy;
use crate::support::kid::resolve_unique_kid;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};

// ============================================================================
// Path Helpers
// ============================================================================

/// Build the key directory path
fn key_dir(keystore_root: &Path, member_id: &str, kid: &str) -> PathBuf {
    keystore_root.join(member_id).join(kid)
}

/// Write key pair files to a temporary directory, cleaning up on failure.
fn save_key_pair_to_tmp(
    tmp_dir: &Path,
    private_key: &PrivateKey,
    public_key: &PublicKey,
) -> Result<()> {
    let result: Result<()> = (|| {
        atomic::save_json_restricted(&tmp_dir.join("private.json"), private_key)?;
        atomic::save_json_restricted(&tmp_dir.join("public.json"), public_key)?;
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
/// 1. Create a temporary directory `<member_id>/.tmp-<uuid>/`
/// 2. Write `private.json` and `public.json`
/// 3. Rename to `<member_id>/<kid>/`
///    The destination directory is either complete or absent.
pub fn save_key_pair_atomic(
    keystore_root: &Path,
    member_id: &str,
    kid: &str,
    private_key: &PrivateKey,
    public_key: &PublicKey,
) -> Result<()> {
    let member_dir = keystore_root.join(member_id);
    ensure_dir_restricted(&member_dir)?;

    let tmp_name = format!(".tmp-{}", uuid::Uuid::new_v4());
    let tmp_dir = member_dir.join(&tmp_name);
    ensure_dir_restricted(&tmp_dir)?;

    save_key_pair_to_tmp(&tmp_dir, private_key, public_key)?;

    let final_dir = member_dir.join(kid);
    fs::rename(&tmp_dir, &final_dir).map_err(|e| {
        Error::io_with_source(
            format!(
                "Failed to rename {} to {}: {}",
                display_path_relative_to_cwd(&tmp_dir),
                display_path_relative_to_cwd(&final_dir),
                e
            ),
            e,
        )
    })?;

    Ok(())
}

/// Load PrivateKey from keystore
pub fn load_private_key(keystore_root: &Path, member_id: &str, kid: &str) -> Result<PrivateKey> {
    let path = key_dir(keystore_root, member_id, kid).join("private.json");
    if let Some(msg) = check_permission_chain(&path, keystore_root)
        .into_iter()
        .next()
    {
        return Err(Error::io(msg));
    }
    parse_private_key_file(&path)
}

/// Load PublicKey from keystore
pub fn load_public_key(keystore_root: &Path, member_id: &str, kid: &str) -> Result<PublicKey> {
    let path = key_dir(keystore_root, member_id, kid).join("public.json");
    for warning in check_permission_chain(&path, keystore_root) {
        tracing::warn!("{}", warning);
    }
    parse_public_key_file(&path)
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
pub fn list_kids(keystore_root: &Path, member_id: &str) -> Result<Vec<String>> {
    let member_path = keystore_root.join(member_id);
    list_directories(
        &member_path,
        |name| name != "active", // Skip "active" file
    )
}

/// List all member IDs in the keystore
///
/// Returns member IDs sorted lexicographically.
pub fn list_member_ids(keystore_root: &Path) -> Result<Vec<String>> {
    list_directories(keystore_root, |_| true)
}

/// Find member_id by kid (scanning all members in keystore)
///
/// Scans all members in the keystore and returns the member_id that owns
/// the given kid directory. Since key directory names use canonical `kid`, at most
/// one member will match.
pub fn find_member_by_kid(keystore_root: &Path, kid: &str) -> Result<String> {
    let member_ids = list_member_ids(keystore_root)?;
    let candidates = member_ids
        .iter()
        .map(|member_id| list_kids(keystore_root, member_id).map(|kids| (member_id, kids)))
        .collect::<Result<Vec<_>>>()?;
    let candidate_kids = candidates
        .iter()
        .flat_map(|(_, kids)| kids.iter().map(String::as_str))
        .collect::<Vec<_>>();
    let resolved_kid = resolve_unique_kid(candidate_kids, kid)?;

    for (member_id, kids) in candidates {
        if kids.iter().any(|candidate| candidate == &resolved_kid) {
            return Ok(member_id.clone());
        }
    }

    Err(Error::NotFound {
        message: format!("kid '{}' not found in keystore", kid_display_lossy(kid)),
    })
}
