// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Path resolution for keystore

use std::path::{Path, PathBuf};

/// Get keystore root directory from base directory
///
/// # Arguments
///
/// * `base_dir` - Base directory (e.g., `~/.config/secretenv/` or `$SECRETENV_HOME/`)
///
/// # Returns
///
/// Path to `base_dir/keys/`
pub fn get_keystore_root_from_base(base_dir: &Path) -> PathBuf {
    base_dir.join("keys")
}

/// Get member keystore path from keystore root
///
/// # Arguments
///
/// * `keystore_root` - Path to keystore root directory
/// * `member_id` - Member ID
///
/// # Returns
///
/// Path to `keystore_root/<member_id>/`
pub fn get_member_keystore_path_from_root(keystore_root: &Path, member_id: &str) -> PathBuf {
    keystore_root.join(member_id)
}

/// Get key path for a specific kid from keystore root
///
/// # Arguments
///
/// * `keystore_root` - Path to keystore root directory
/// * `member_id` - Member ID
/// * `kid` - Key ID
///
/// # Returns
///
/// Path to `keystore_root/<member_id>/<kid>/`
pub fn get_key_path_from_root(keystore_root: &Path, member_id: &str, kid: &str) -> PathBuf {
    get_member_keystore_path_from_root(keystore_root, member_id).join(kid)
}

/// Get private key file path from keystore root
///
/// # Arguments
///
/// * `keystore_root` - Path to keystore root directory
/// * `member_id` - Member ID
/// * `kid` - Key ID
///
/// # Returns
///
/// Path to `keystore_root/<member_id>/<kid>/private.json`
pub fn get_private_key_file_path_from_root(
    keystore_root: &Path,
    member_id: &str,
    kid: &str,
) -> PathBuf {
    get_key_path_from_root(keystore_root, member_id, kid).join("private.json")
}

/// Get public key file path from keystore root
///
/// # Arguments
///
/// * `keystore_root` - Path to keystore root directory
/// * `member_id` - Member ID
/// * `kid` - Key ID
///
/// # Returns
///
/// Path to `keystore_root/<member_id>/<kid>/public.json`
pub fn get_public_key_file_path_from_root(
    keystore_root: &Path,
    member_id: &str,
    kid: &str,
) -> PathBuf {
    get_key_path_from_root(keystore_root, member_id, kid).join("public.json")
}

/// Get active key file path from keystore root
///
/// # Arguments
///
/// * `keystore_root` - Path to keystore root directory
/// * `member_id` - Member ID
///
/// # Returns
///
/// Path to `keystore_root/<member_id>/active`
pub fn get_active_file_path_from_root(keystore_root: &Path, member_id: &str) -> PathBuf {
    get_member_keystore_path_from_root(keystore_root, member_id).join("active")
}
