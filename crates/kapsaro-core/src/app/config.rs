// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer orchestration for config commands.

use crate::app::context::options::CommonCommandOptions;
use crate::config::resolution::global;
use crate::io::config::store::{config_key_not_found, set_config_value, unset_config_value};
use crate::Result;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigScope {
    Global,
}

#[derive(Debug)]
pub struct ConfigSetResult {
    pub key: String,
    pub value: String,
    pub scope: ConfigScope,
}

#[derive(Debug)]
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
    global::resolve_config_value(key, Some(base_dir))?.ok_or_else(|| config_key_not_found(key))
}

fn list_config(base_dir: &std::path::Path) -> Result<BTreeMap<String, String>> {
    global::load_global_config(Some(base_dir))
}

/// Write a configuration value, creating the local state home when missing.
fn set_config(key: &str, value: &str, base_dir: &std::path::Path) -> Result<ConfigSetResult> {
    let normalized = global::normalize_key(key)?;
    let home = global::create_home(base_dir)?;
    set_config_value(&home, &normalized, value)?;
    Ok(ConfigSetResult {
        key: normalized,
        value: value.to_string(),
        scope: ConfigScope::Global,
    })
}

/// Remove a configuration value from an existing local state home.
///
/// Removing a key never has anything to write, so an absent home is reported as
/// the missing key rather than created as a side effect of the failed command.
fn unset_config(key: &str, base_dir: &std::path::Path) -> Result<ConfigUnsetResult> {
    let normalized = global::normalize_key(key)?;
    let Some(home) = global::open_optional_home(base_dir)? else {
        return Err(config_key_not_found(&normalized));
    };
    unset_config_value(&home, &normalized)?;
    Ok(ConfigUnsetResult {
        key: normalized,
        scope: ConfigScope::Global,
    })
}

#[cfg(test)]
#[path = "../../tests/unit/internal/app_config_test.rs"]
mod tests;
