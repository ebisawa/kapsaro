// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust store path resolution.
//! Owns the single spelling of the trust directory and of one owner's file.

use crate::model::identity::MemberHandle;
use std::path::{Path, PathBuf};

/// Name of the trust store directory.
pub(crate) const TRUST_DIR_NAME: &str = "trust";

/// Trust store directory: `<base_dir>/trust/`
pub fn get_trust_store_dir(base_dir: &Path) -> PathBuf {
    base_dir.join(TRUST_DIR_NAME)
}

/// Suffix every trust store file name ends in.
const TRUST_STORE_FILE_SUFFIX: &str = ".json";

/// Trust store file name inside the trust directory: `<owner_handle>.json`
pub fn get_trust_store_file_name(owner_handle: &MemberHandle) -> String {
    format!("{}{}", owner_handle.as_str(), TRUST_STORE_FILE_SUFFIX)
}

/// The owner handle a trust store file name is built from.
///
/// `None` means the name is not spelled the way this module spells one, so it
/// names no trust store whatever it holds.
pub(crate) fn get_trust_store_owner_handle(file_name: &str) -> Option<&str> {
    file_name.strip_suffix(TRUST_STORE_FILE_SUFFIX)
}

/// Trust store file path: `<base_dir>/trust/<owner_handle>.json`
pub fn get_trust_store_file_path(base_dir: &Path, owner_handle: &MemberHandle) -> PathBuf {
    get_trust_store_dir(base_dir).join(get_trust_store_file_name(owner_handle))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_trust_paths_test.rs"]
mod io_trust_paths_test;
