// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer orchestration for config commands.

use crate::app::context::options::CommonCommandOptions;
use crate::feature::config::{self};
use crate::io::config::store::{set_config_value, unset_config_value};
use crate::{Error, Result};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigScope {
    Global,
}

pub(crate) struct ConfigSetResult {
    pub key: String,
    pub value: String,
    pub scope: ConfigScope,
}

pub(crate) struct ConfigUnsetResult {
    pub key: String,
    pub scope: ConfigScope,
}

pub(crate) fn resolve_config_value_command(
    options: &CommonCommandOptions,
    key: &str,
) -> Result<String> {
    let base_dir = options.resolve_base_dir()?;
    resolve_config_value(key, &base_dir)
}

pub(crate) fn list_config_command(
    options: &CommonCommandOptions,
) -> Result<BTreeMap<String, String>> {
    let base_dir = options.resolve_base_dir()?;
    list_config(&base_dir)
}

pub(crate) fn set_config_command(
    options: &CommonCommandOptions,
    key: &str,
    value: &str,
) -> Result<ConfigSetResult> {
    let base_dir = options.resolve_base_dir()?;
    set_config(key, value, &base_dir)
}

pub(crate) fn unset_config_command(
    options: &CommonCommandOptions,
    key: &str,
) -> Result<ConfigUnsetResult> {
    let base_dir = options.resolve_base_dir()?;
    unset_config(key, &base_dir)
}

fn resolve_config_value(key: &str, base_dir: &std::path::Path) -> Result<String> {
    let normalized = config::normalize_key(key)?;
    let value = config::resolve_config_value(&normalized, Some(base_dir))?.value;
    value.ok_or_else(|| Error::NotFound {
        message: format!("Configuration key '{}' not found", key),
    })
}

fn list_config(base_dir: &std::path::Path) -> Result<BTreeMap<String, String>> {
    config::load_global_config(Some(base_dir))
}

fn set_config(key: &str, value: &str, base_dir: &std::path::Path) -> Result<ConfigSetResult> {
    let normalized = config::normalize_key(key)?;
    let resolution = config::resolve_config_location(Some(base_dir))?;
    set_config_value(&resolution.path, &normalized, value)?;
    Ok(ConfigSetResult {
        key: key.to_string(),
        value: value.to_string(),
        scope: resolution.scope.into(),
    })
}

fn unset_config(key: &str, base_dir: &std::path::Path) -> Result<ConfigUnsetResult> {
    let normalized = config::normalize_key(key)?;
    let resolution = config::resolve_config_location(Some(base_dir))?;
    unset_config_value(&resolution.path, &normalized)?;
    Ok(ConfigUnsetResult {
        key: key.to_string(),
        scope: resolution.scope.into(),
    })
}

impl From<crate::feature::config::ConfigScope> for ConfigScope {
    fn from(scope: crate::feature::config::ConfigScope) -> Self {
        match scope {
            crate::feature::config::ConfigScope::Global => Self::Global,
        }
    }
}
