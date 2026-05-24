// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Global config.toml key resolution helpers.
//! Owns supported-key normalization and flat global config loading.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::config::types::ConfigKey;
use crate::io::config;
use crate::Result;

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
    Ok(ConfigKey::parse(key)?.canonical_name().to_string())
}

pub fn validate_key(key: &str) -> Result<()> {
    let _ = ConfigKey::parse(key)?;
    Ok(())
}

pub fn resolve_config_value(key: &str, base_dir: Option<&Path>) -> Result<ConfigValueResolution> {
    let normalized = normalize_key(key)?;
    if let Some(value) = load_global_config(base_dir)?.get(&normalized) {
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
