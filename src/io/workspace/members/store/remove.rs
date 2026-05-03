// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::super::paths::get_active_member_file_path;
use crate::{Error, Result};
use std::fs;
use std::path::Path;

pub fn remove_member(workspace_path: &Path, member_handle: &str) -> Result<()> {
    let active_path = get_active_member_file_path(workspace_path, member_handle);
    if !active_path.exists() {
        return Err(Error::NotFound {
            message: format!("Member '{}' not found in active/", member_handle),
        });
    }

    fs::remove_file(&active_path).map_err(|e| {
        Error::build_io_error_with_source(
            format!("Failed to remove member '{}': {}", member_handle, e),
            e,
        )
    })
}
