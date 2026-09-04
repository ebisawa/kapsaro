// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Configuration file storage operations
//!
//! Reads and writes the global config.toml as flat TOML key-value pairs.
//! Every access is relative to an already opened local-state home descriptor.

use crate::io::document_store;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::{
    format_unreplaceable_child_type, optional_child_type_at, save_text_restricted_at, DirectoryFd,
};
use crate::support::limits::MAX_CONFIG_FILE_SIZE;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::path::Path;

const CONFIG_FILE_SUBJECT: &str = "config file";
const CONFIG_FILE_NAME: &str = "config.toml";

/// Load global configuration from a previously opened local-state home.
///
/// Returns a map of string keys to string values. Only string values are
/// extracted, and a home without a config file yields an empty map.
///
/// # Errors
///
/// - `Error::Io` - Cannot read the file
/// - `Error::Parse` - Invalid TOML format
pub(crate) fn load_config_file_from_anchored_home(
    home: &AnchoredDir,
) -> Result<BTreeMap<String, String>> {
    Ok(string_values(load_toml_table(home)?))
}

fn string_values(table: toml::Table) -> BTreeMap<String, String> {
    table
        .into_iter()
        .filter_map(|(key, value)| value.as_str().map(|value| (key, value.to_string())))
        .collect()
}

/// Set a configuration value in the config file of an opened home.
///
/// Concurrent updates use last-writer-wins; atomic replacement keeps the file complete.
///
/// # Errors
///
/// - `Error::Io` - Cannot read or write the file
/// - `Error::Parse` - Invalid TOML format
pub(crate) fn set_config_value(home: &AnchoredDir, key: &str, value: &str) -> Result<()> {
    let mut table = load_toml_table(home)?;
    table.insert(key.to_string(), toml::Value::String(value.to_string()));
    save_toml_table(home, &table)
}

/// Remove a configuration value from the config file of an opened home.
///
/// Concurrent updates use last-writer-wins; atomic replacement keeps the file complete.
///
/// # Errors
///
/// - `Error::NotFound` - Key not found
/// - `Error::Io` - Cannot read or write the file
/// - `Error::Parse` - Invalid TOML format
pub(crate) fn unset_config_value(home: &AnchoredDir, key: &str) -> Result<()> {
    let mut table = load_toml_table(home)?;
    if table.remove(key).is_none() {
        return Err(config_key_not_found(key));
    }
    save_toml_table(home, &table)
}

/// The single wording for a configuration key that is not set.
pub(crate) fn config_key_not_found(key: &str) -> Error {
    Error::build_not_found_error(format!("Configuration key '{}' not found", key))
}

/// Load the config table relative to an opened home, empty when absent.
fn load_toml_table<D>(home: &D) -> Result<toml::Table>
where
    D: DirectoryFd,
{
    let path = home.path().join(CONFIG_FILE_NAME);
    let permission_chain: [&dyn DirectoryFd; 1] = [home];
    let loaded = document_store::load_optional_at(
        home,
        &path,
        &permission_chain,
        MAX_CONFIG_FILE_SIZE,
        CONFIG_FILE_SUBJECT,
        |content| parse_toml_table(content, &path),
    )?;
    Ok(loaded.map(|loaded| loaded.document).unwrap_or_default())
}

fn parse_toml_table(content: &str, path: &Path) -> Result<toml::Table> {
    toml::from_str(content).map_err(|e| {
        Error::build_parse_error_with_source(
            format!(
                "Invalid TOML in config file '{}': {}",
                format_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })
}

/// Save a TOML table atomically, relative to an opened home.
fn save_toml_table<D>(home: &D, table: &toml::Table) -> Result<()>
where
    D: DirectoryFd,
{
    enforce_replaceable_config_file(home)?;
    let content = toml::to_string_pretty(table).map_err(|e| {
        Error::build_parse_error_with_source(format!("Failed to serialize config: {}", e), e)
    })?;
    save_text_restricted_at(home, CONFIG_FILE_NAME, &content)
}

/// Refuse a config name the write must not take over.
///
/// An entry that is not a regular file is not a file kapsaro wrote, and the
/// rename that publishes the write would replace it: the link or directory
/// standing there is the only sign the name was repointed, so it is reported
/// rather than erased. The read path refuses the same entries, so a config file
/// kapsaro declines to read is one it declines to overwrite.
fn enforce_replaceable_config_file<D>(home: &D) -> Result<()>
where
    D: DirectoryFd,
{
    let Some(child_type) = optional_child_type_at(home, CONFIG_FILE_NAME)? else {
        return Ok(());
    };
    let Some(description) = format_unreplaceable_child_type(child_type) else {
        return Ok(());
    };
    Err(Error::build_invalid_operation_error(format!(
        "refusing to replace {} standing where the config file belongs: {}",
        description,
        format_path_relative_to_cwd(&home.path().join(CONFIG_FILE_NAME))
    )))
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_config_store_test.rs"]
mod io_config_store_test;
