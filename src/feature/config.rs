// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Config feature - configuration operations.

use crate::io::config;
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// Keep this list aligned with the supported global config.toml keys.
pub(crate) const VALID_KEYS: &[&str] = &[
    "member_handle",
    "workspace",
    "ssh_identity",
    "ssh_keygen_command",
    "ssh_add_command",
    "ssh_signing_method",
    "github_user",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigScope {
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigValueResolution {
    pub value: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigLocation {
    pub path: PathBuf,
    pub scope: ConfigScope,
}

pub(crate) fn normalize_key(key: &str) -> Result<String> {
    // User-facing convenience:
    // historically some users typed `gihub_user` (typo). Normalize to the canonical key.
    if key == "gihub_user" {
        return Ok("github_user".to_string());
    }

    if VALID_KEYS.contains(&key) {
        Ok(key.to_string())
    } else {
        Err(Error::InvalidArgument {
            message: format!(
                "invalid key '{}'. Valid keys: {}",
                key,
                VALID_KEYS.join(", ")
            ),
        })
    }
}

pub fn validate_key(key: &str) -> Result<()> {
    let _ = normalize_key(key)?;
    Ok(())
}

pub fn resolve_config_value(key: &str, base_dir: Option<&Path>) -> Result<ConfigValueResolution> {
    if let Some(value) = load_global_config(base_dir)?.get(key) {
        return Ok(ConfigValueResolution {
            value: Some(value.clone()),
            scope: Some("global".to_string()),
        });
    }

    Ok(ConfigValueResolution {
        value: None,
        scope: None,
    })
}

pub fn resolve_config_location(base_dir: Option<&Path>) -> Result<ConfigLocation> {
    let config_path = match base_dir {
        Some(dir) => config::paths::get_global_config_path_from_base(dir),
        None => config::paths::get_global_config_path()?,
    };
    Ok(ConfigLocation {
        path: config_path,
        scope: ConfigScope::Global,
    })
}

pub fn load_global_config(base_dir: Option<&Path>) -> Result<BTreeMap<String, String>> {
    let base_dir = match base_dir {
        Some(dir) => dir.to_path_buf(),
        None => config::paths::get_base_dir()?,
    };
    let config_path = config::paths::get_global_config_path_from_base(&base_dir);
    config::store::load_config_file(&config_path, &base_dir)
}
