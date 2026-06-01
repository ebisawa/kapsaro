// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer orchestration for config commands.

use crate::app::context::options::CommonCommandOptions;
use crate::config::resolution::global;
use crate::io::config::store::{set_config_value, unset_config_value};
use crate::{Error, Result};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigScope {
    Global,
}

pub struct ConfigSetResult {
    pub key: String,
    pub value: String,
    pub scope: ConfigScope,
}

pub struct ConfigUnsetResult {
    pub key: String,
    pub scope: ConfigScope,
}

pub fn resolve_config_value_command(options: &CommonCommandOptions, key: &str) -> Result<String> {
    let base_dir = options.resolve_base_dir()?;
    resolve_config_value(key, &base_dir)
}

pub fn list_config_command(options: &CommonCommandOptions) -> Result<BTreeMap<String, String>> {
    let base_dir = options.resolve_base_dir()?;
    list_config(&base_dir)
}

pub fn set_config_command(
    options: &CommonCommandOptions,
    key: &str,
    value: &str,
) -> Result<ConfigSetResult> {
    let base_dir = options.resolve_base_dir()?;
    set_config(key, value, &base_dir)
}

pub fn unset_config_command(
    options: &CommonCommandOptions,
    key: &str,
) -> Result<ConfigUnsetResult> {
    let base_dir = options.resolve_base_dir()?;
    unset_config(key, &base_dir)
}

fn resolve_config_value(key: &str, base_dir: &std::path::Path) -> Result<String> {
    let normalized = global::normalize_key(key)?;
    let value = global::resolve_config_value(&normalized, Some(base_dir))?.value;
    value.ok_or_else(|| {
        Error::build_not_found_error(format!("Configuration key '{}' not found", key))
    })
}

fn list_config(base_dir: &std::path::Path) -> Result<BTreeMap<String, String>> {
    global::load_global_config(Some(base_dir))
}

fn set_config(key: &str, value: &str, base_dir: &std::path::Path) -> Result<ConfigSetResult> {
    let normalized = global::normalize_key(key)?;
    let resolution = global::resolve_config_location(Some(base_dir))?;
    set_config_value(&resolution.path, &normalized, value)?;
    Ok(ConfigSetResult {
        key: normalized,
        value: value.to_string(),
        scope: resolution.scope.into(),
    })
}

fn unset_config(key: &str, base_dir: &std::path::Path) -> Result<ConfigUnsetResult> {
    let normalized = global::normalize_key(key)?;
    let resolution = global::resolve_config_location(Some(base_dir))?;
    unset_config_value(&resolution.path, &normalized)?;
    Ok(ConfigUnsetResult {
        key: normalized,
        scope: resolution.scope.into(),
    })
}

impl From<crate::config::resolution::global::ConfigScope> for ConfigScope {
    fn from(scope: crate::config::resolution::global::ConfigScope) -> Self {
        match scope {
            crate::config::resolution::global::ConfigScope::Global => Self::Global,
        }
    }
}
