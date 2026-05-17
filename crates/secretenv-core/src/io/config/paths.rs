// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Configuration path resolution
//!
//! Provides functions to resolve paths for configuration files.

use crate::{Error, Result};
use std::env;
use std::path::{Path, PathBuf};

/// Get the base directory for secretenv configuration and keys
///
/// Returns the absolute path to the base directory based on environment variables.
///
/// # Priority
///
/// 1. `$SECRETENV_HOME`
/// 2. `~/.config/secretenv/`
///
/// # Errors
///
/// Returns `Error::Config` if `HOME` environment variable is not set.
pub fn get_base_dir() -> Result<PathBuf> {
    if let Ok(home) = env::var("SECRETENV_HOME") {
        return Ok(PathBuf::from(home));
    }

    env::var("HOME")
        .map(|p| PathBuf::from(p).join(".config").join("secretenv"))
        .map_err(|_| Error::build_config_error("HOME environment variable not set".to_string()))
}

/// Resolve the global configuration file path
///
/// Returns the absolute path to the global config file based on environment variables.
/// Does NOT check if the file exists.
///
/// # Priority
///
/// 1. `$SECRETENV_HOME/config.toml`
/// 2. `~/.config/secretenv/config.toml`
///
/// # Errors
///
/// Returns `Error::Config` if `HOME` environment variable is not set.
pub fn get_global_config_path() -> Result<PathBuf> {
    Ok(get_base_dir()?.join("config.toml"))
}

/// Resolve the global configuration file path from an explicit base_dir
///
/// # Arguments
///
/// * `base_dir` - Base directory (e.g., `~/.config/secretenv/` or `$SECRETENV_HOME/`)
///
/// # Returns
///
/// Path to `base_dir/config.toml`
pub fn get_global_config_path_from_base(base_dir: &Path) -> PathBuf {
    base_dir.join("config.toml")
}
