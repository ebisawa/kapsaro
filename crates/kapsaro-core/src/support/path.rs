// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0
//! Path display helpers.

use std::path::Path;

/// Display a path relative to the current working directory when possible.
///
/// If `strip_prefix(cwd)` fails, falls back to the original `path.display()`.
pub fn format_path_relative_to_cwd(path: &Path) -> String {
    let cwd = std::env::current_dir().ok();
    if let Some(cwd) = cwd {
        if let Ok(relative) = path.strip_prefix(&cwd) {
            return relative.display().to_string();
        }
    }
    path.display().to_string()
}
