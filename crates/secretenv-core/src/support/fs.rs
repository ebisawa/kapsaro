// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Atomic filesystem operations.

pub mod atomic;
pub mod lock;
pub(crate) mod permission;
pub(crate) mod policy;
pub(crate) mod read;
pub(crate) mod snapshot;

pub use permission::{
    check_permission_chain, ensure_dir, ensure_dir_restricted, set_file_permission_0600,
};
pub use read::{load_bytes, load_text, load_text_with_limit};
pub use snapshot::ensure_text_file_matches_snapshot_with_limit;

use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::fs;
use std::fs::ReadDir;
use std::path::Path;

/// List directory entries with consistent path-aware error messages.
pub fn list_dir(path: &Path) -> Result<ReadDir> {
    fs::read_dir(path).map_err(|e| {
        Error::build_io_error_with_source(
            format!(
                "Failed to read directory {}: {}",
                format_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })
}
