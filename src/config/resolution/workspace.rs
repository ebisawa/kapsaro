// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace resolution from global config

use crate::Result;
use std::path::PathBuf;

use super::common::{expand_tilde, load_field_from_global_config};

/// Resolve workspace path from global config.toml
///
/// Reads the `workspace` key from `~/.config/secretenv/config.toml`
/// (or `$SECRETENV_HOME/config.toml`). Returns `None` if not configured.
///
/// Tilde (`~`) in the path is expanded to the HOME directory.
pub(crate) fn resolve_workspace_from_config() -> Result<Option<PathBuf>> {
    let value = load_field_from_global_config("workspace", None)?;
    match value {
        Some(path_str) => {
            let expanded = expand_tilde(&path_str)?;
            Ok(Some(expanded))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/config_resolution_workspace_test.rs"]
mod tests;
