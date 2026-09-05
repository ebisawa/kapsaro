// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Path resolution for keystore

use super::access::{PRIVATE_KEY_FILE, PUBLIC_KEY_FILE};
use crate::model::identity::{Kid, MemberHandle};
use std::path::{Path, PathBuf};

/// Name of the keystore root directory under a local state home.
pub(crate) const KEYSTORE_DIR_NAME: &str = "keys";

/// Get keystore root directory from base directory
///
/// # Arguments
///
/// * `base_dir` - Base directory (e.g., `~/.config/kapsaro/` or `$KAPSARO_HOME/`)
///
/// # Returns
///
/// Path to `base_dir/keys/`
pub fn get_keystore_root_from_base(base_dir: &Path) -> PathBuf {
    base_dir.join(KEYSTORE_DIR_NAME)
}

/// Get private key file path from keystore root
///
/// # Arguments
///
/// * `keystore_root` - Path to keystore root directory
/// * `member_handle` - Member handle
/// * `kid` - Key ID
///
/// # Returns
///
/// Path to `keystore_root/<member_handle>/<kid>/private.json`
pub fn get_private_key_file_path_from_root(
    keystore_root: &Path,
    member_handle: &MemberHandle,
    kid: &Kid,
) -> PathBuf {
    get_key_dir_from_root(keystore_root, member_handle, kid).join(PRIVATE_KEY_FILE)
}

/// Get public key file path from keystore root
///
/// # Arguments
///
/// * `keystore_root` - Path to keystore root directory
/// * `member_handle` - Member handle
/// * `kid` - Key ID
///
/// # Returns
///
/// Path to `keystore_root/<member_handle>/<kid>/public.json`
pub fn get_public_key_file_path_from_root(
    keystore_root: &Path,
    member_handle: &MemberHandle,
    kid: &Kid,
) -> PathBuf {
    get_key_dir_from_root(keystore_root, member_handle, kid).join(PUBLIC_KEY_FILE)
}

/// Directory holding both key documents: `keystore_root/<member_handle>/<kid>/`
fn get_key_dir_from_root(keystore_root: &Path, member_handle: &MemberHandle, kid: &Kid) -> PathBuf {
    keystore_root
        .join(member_handle.as_str())
        .join(kid.as_str())
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_keystore_paths_test.rs"]
mod io_keystore_paths_test;
