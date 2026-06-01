// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Common utilities for configuration resolution

use crate::{Error, Result};
use std::env;
use std::path::{Path, PathBuf};

use crate::config::types::ConfigKey;
use crate::io::config::paths::get_global_config_path_from_base;
use crate::io::config::store::load_config_file;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StringSourceResolution {
    Cli,
    Env,
    GlobalConfig,
    Default,
}

/// Load a config field from global config (KAPSARO_HOME/config.toml)
pub(crate) fn load_field_from_global_config(
    field_name: &str,
    base_dir: Option<&Path>,
) -> Result<Option<String>> {
    let base_dir = match base_dir {
        Some(dir) => dir.to_path_buf(),
        None => crate::io::config::paths::get_base_dir()?,
    };
    let config_path = get_global_config_path_from_base(&base_dir);
    let config = load_config_file(&config_path, &base_dir)?;
    Ok(config.get(field_name).cloned())
}

/// Expand tilde (~) in path to HOME directory
pub(crate) fn expand_tilde(path: &str) -> Result<PathBuf> {
    if path == "~" {
        return get_home_dir();
    }
    if let Some(stripped) = path.strip_prefix("~/") {
        return Ok(get_home_dir()?.join(stripped));
    }
    Ok(PathBuf::from(path))
}

/// Get HOME directory from environment
pub(super) fn get_home_dir() -> Result<PathBuf> {
    env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| Error::build_config_error("HOME environment variable not set".to_string()))
}

/// Get default SSH key path (~/.ssh/id_ed25519)
pub(super) fn get_default_ssh_key_path() -> Result<PathBuf> {
    Ok(get_home_dir()?.join(".ssh").join("id_ed25519"))
}

/// Resolve a string value with priority order (optional value version)
///
/// Priority order:
/// 1. CLI value (if provided)
/// 2. Environment variable (if env_var_name is provided)
/// 3. Global config
/// 4. Default value (if provided)
///
/// Returns the first value found, or None if no value is found and no default is provided.
pub(super) fn resolve_string_with_source(
    cli_value: Option<String>,
    env_var_name: Option<&str>,
    config_key: &str,
    base_dir: Option<&Path>,
    default: Option<String>,
) -> Result<Option<(String, StringSourceResolution)>> {
    // Priority 1: CLI value
    if let Some(value) = cli_value {
        return Ok(Some((value, StringSourceResolution::Cli)));
    }

    // Priority 2: Environment variable
    if let Some(env_var) = env_var_name {
        if let Ok(value) = env::var(env_var) {
            return Ok(Some((value, StringSourceResolution::Env)));
        }
    }

    // Priority 3: Global config
    if let Some(value) = load_field_from_global_config(config_key, base_dir)? {
        return Ok(Some((value, StringSourceResolution::GlobalConfig)));
    }

    // Priority 4: Default value
    Ok(default.map(|value| (value, StringSourceResolution::Default)))
}

pub(super) fn resolve_string_with_priority(
    cli_value: Option<String>,
    env_var_name: Option<&str>,
    config_key: &str,
    base_dir: Option<&Path>,
    default: Option<String>,
) -> Result<Option<String>> {
    Ok(
        resolve_string_with_source(cli_value, env_var_name, config_key, base_dir, default)?
            .map(|(value, _)| value),
    )
}

/// Resolve a string value with priority order (required value version)
///
/// This version requires a default value and always returns a String.
/// Use this when you need a guaranteed value (e.g., command paths with defaults).
///
/// Priority order:
/// 1. CLI value (if provided)
/// 2. Environment variable (if env_var_name is provided)
/// 3. Global config
/// 4. Default value (required)
///
/// # Errors
/// Returns `Error::Config` if no value is found and no default is provided (should not happen).
pub(super) fn resolve_string_required(
    cli_value: Option<String>,
    env_var_name: Option<&str>,
    config_key: &str,
    base_dir: Option<&Path>,
    default: String,
) -> Result<String> {
    resolve_string_with_priority(cli_value, env_var_name, config_key, base_dir, Some(default))?
        .ok_or_else(|| {
            Error::build_config_error(format!(
                "Required config value '{}' could not be resolved",
                config_key
            ))
        })
}

fn resolve_command_path(
    config_key: &str,
    default_command: &str,
    base_dir: Option<&Path>,
) -> Result<String> {
    resolve_string_required(
        None,
        None,
        config_key,
        base_dir,
        default_command.to_string(),
    )
}

/// Resolve SSH command path (ssh-keygen or ssh-add) from config
///
/// Priority order:
/// 1. Global config
/// 2. Default value
pub(crate) fn resolve_ssh_keygen_path(base_dir: Option<&Path>) -> Result<String> {
    resolve_command_path(
        ConfigKey::SshKeygenCommand.canonical_name(),
        "ssh-keygen",
        base_dir,
    )
}

/// Resolve ssh-add command path from config
///
/// Priority order:
/// 1. Global config
/// 2. Default value
pub(crate) fn resolve_ssh_add_path(base_dir: Option<&Path>) -> Result<String> {
    resolve_command_path(
        ConfigKey::SshAddCommand.canonical_name(),
        "ssh-add",
        base_dir,
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/config_resolution_common_test.rs"]
mod tests;
