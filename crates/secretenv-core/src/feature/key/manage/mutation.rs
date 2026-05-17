// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::feature::key::types::{KeyActivateResult, KeyRemoveResult};
use crate::io::keystore::active::{clear_active_kid, load_active_kid, set_active_kid};
use crate::io::keystore::helpers::resolve_member_kid_query;
use crate::io::keystore::member::{remove_key_directory, select_latest_valid_kid};
use crate::io::keystore::paths::get_private_key_file_path_from_root;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

use super::common::resolve_keystore_root;

pub fn activate_key(
    home: Option<PathBuf>,
    member_handle: String,
    kid: Option<String>,
) -> Result<KeyActivateResult> {
    let keystore_root = resolve_keystore_root(home)?;
    let kid = resolve_activated_kid(&keystore_root, &member_handle, kid)?;
    validate_key_exists(&keystore_root, &member_handle, &kid)?;
    set_active_kid(&member_handle, &kid, &keystore_root)?;
    Ok(KeyActivateResult { member_handle, kid })
}

pub fn remove_key(
    home: Option<PathBuf>,
    member_handle: String,
    kid: String,
    force: bool,
) -> Result<KeyRemoveResult> {
    let keystore_root = resolve_keystore_root(home)?;
    let kid = resolve_member_kid_query(&keystore_root, &member_handle, &kid)?;
    validate_key_directory_exists(&keystore_root, &member_handle, &kid)?;
    let was_active = load_active_kid(&member_handle, &keystore_root)?.as_ref() == Some(&kid);
    validate_key_removal(&kid, was_active, force)?;
    remove_key_directory(&keystore_root, &member_handle, &kid)?;

    if was_active {
        clear_active_kid(&member_handle, &keystore_root)?;
    }

    Ok(KeyRemoveResult {
        member_handle,
        kid,
        was_active,
    })
}

fn resolve_activated_kid(
    keystore_root: &Path,
    member_handle: &str,
    kid: Option<String>,
) -> Result<String> {
    match kid {
        Some(kid) => resolve_member_kid_query(keystore_root, member_handle, &kid),
        None => select_latest_valid_kid(keystore_root, member_handle),
    }
}

fn validate_key_exists(keystore_root: &Path, member_handle: &str, kid: &str) -> Result<()> {
    let private_key_path = get_private_key_file_path_from_root(keystore_root, member_handle, kid);
    if private_key_path.exists() {
        return Ok(());
    }

    Err(Error::build_not_found_error(format!(
        "Key not found: {}",
        kid
    )))
}

fn validate_key_directory_exists(
    keystore_root: &Path,
    member_handle: &str,
    kid: &str,
) -> Result<()> {
    let key_dir = keystore_root.join(member_handle).join(kid);
    if key_dir.exists() {
        return Ok(());
    }

    Err(Error::build_not_found_error(format!(
        "Key not found: {}",
        kid
    )))
}

fn validate_key_removal(kid: &str, was_active: bool, force: bool) -> Result<()> {
    if !was_active || force {
        return Ok(());
    }

    Err(Error::build_config_error(format!(
        "Cannot remove active key '{}'. Use --force to remove anyway.",
        kid
    )))
}
