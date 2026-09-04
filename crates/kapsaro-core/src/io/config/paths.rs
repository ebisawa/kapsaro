// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Configuration path resolution
//!
//! Provides functions to resolve paths for configuration files.

use std::path::{Path, PathBuf};

/// Resolve the global configuration file path from an explicit base_dir
///
/// # Arguments
///
/// * `base_dir` - Base directory (e.g., `~/.config/kapsaro/` or `$KAPSARO_HOME/`)
///
/// # Returns
///
/// Path to `base_dir/config.toml`
pub fn get_global_config_path_from_base(base_dir: &Path) -> PathBuf {
    base_dir.join("config.toml")
}
