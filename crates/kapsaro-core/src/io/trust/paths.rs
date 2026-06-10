// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust store path resolution.

use std::path::{Path, PathBuf};

/// Trust store directory: `<base_dir>/trust/`
pub fn get_trust_store_dir(base_dir: &Path) -> PathBuf {
    base_dir.join("trust")
}

/// Trust store file path: `<base_dir>/trust/<owner_handle>.json`
pub fn get_trust_store_file_path(base_dir: &Path, owner_handle: &str) -> PathBuf {
    get_trust_store_dir(base_dir).join(format!("{}.json", owner_handle))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_trust_paths_test.rs"]
mod io_trust_paths_test;
