// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Configuration file storage operations
//!
//! Provides functions to read and write configuration files as flat TOML key-value pairs.
//! Global config.toml load and save operations.

use crate::io::document_store::{CollectPermissionWarnings, DocumentStore};
use crate::support::fs::lock;
use crate::support::limits::MAX_CONFIG_FILE_SIZE;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::path::Path;

const CONFIG_FILE_SUBJECT: &str = "config file";

/// Load configuration from a TOML file as flat key-value pairs
///
/// Returns a map of string keys to string values. Only string values are extracted.
/// If the file doesn't exist, returns an empty map.
///
/// # Arguments
///
/// * `path` - Path to the config file
///
/// # Errors
///
/// - `Error::Io` - Cannot read the file
/// - `Error::Parse` - Invalid TOML format
pub fn load_config_file(path: &Path, base_dir: &Path) -> Result<BTreeMap<String, String>> {
    let Some(loaded) = DocumentStore::<CollectPermissionWarnings>::load_optional(
        path,
        base_dir,
        MAX_CONFIG_FILE_SIZE,
        CONFIG_FILE_SUBJECT,
        |content| parse_toml_table(content, path),
    )?
    else {
        return Ok(BTreeMap::new());
    };
    for warning in loaded.permission_warnings {
        tracing::warn!("{}", warning);
    }

    let mut config = BTreeMap::new();
    for (key, value) in loaded.document {
        if let Some(s) = value.as_str() {
            config.insert(key, s.to_string());
        }
    }

    Ok(config)
}

/// Set a configuration value in a TOML file
///
/// Uses file locking to ensure atomic updates.
///
/// # Arguments
///
/// * `path` - Path to the config file
/// * `key` - Configuration key
/// * `value` - Configuration value
///
/// # Errors
///
/// - `Error::Io` - Cannot read or write the file
/// - `Error::Parse` - Invalid TOML format
pub fn set_config_value(path: &Path, key: &str, value: &str) -> Result<()> {
    lock::with_file_lock(path, || {
        let mut table = load_toml_table(path)?;
        table.insert(key.to_string(), toml::Value::String(value.to_string()));
        save_toml_table(path, &table)
    })
}

/// Remove a configuration value from a TOML file
///
/// Uses file locking to ensure atomic updates.
///
/// # Arguments
///
/// * `path` - Path to the config file
/// * `key` - Configuration key to remove
///
/// # Errors
///
/// - `Error::NotFound` - Key not found
/// - `Error::Io` - Cannot read or write the file
/// - `Error::Parse` - Invalid TOML format
pub fn unset_config_value(path: &Path, key: &str) -> Result<()> {
    lock::with_file_lock(path, || {
        let mut table = load_toml_table(path)?;
        if table.remove(key).is_none() {
            return Err(Error::NotFound {
                message: format!("Configuration key '{}' not found", key),
            });
        }
        save_toml_table(path, &table)
    })
}

/// Load a TOML table from a file
fn load_toml_table(path: &Path) -> Result<toml::Table> {
    if !path.exists() {
        return Ok(toml::Table::new());
    }

    DocumentStore::<CollectPermissionWarnings>::load_required(
        path,
        path.parent().unwrap_or_else(|| Path::new(".")),
        MAX_CONFIG_FILE_SIZE,
        CONFIG_FILE_SUBJECT,
        |content| parse_toml_table(content, path),
    )
    .map(|loaded| loaded.document)
}

fn parse_toml_table(content: &str, path: &Path) -> Result<toml::Table> {
    toml::from_str(content).map_err(|e| Error::Parse {
        message: format!(
            "Invalid TOML in config file '{}': {}",
            format_path_relative_to_cwd(path),
            e
        ),
        source: Some(Box::new(e)),
    })
}

/// Save a TOML table to a file atomically
fn save_toml_table(path: &Path, table: &toml::Table) -> Result<()> {
    let content = toml::to_string_pretty(table).map_err(|e| Error::Parse {
        message: format!("Failed to serialize config: {}", e),
        source: Some(Box::new(e)),
    })?;
    DocumentStore::<CollectPermissionWarnings>::save_text_restricted(path, &content)
}
