// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Global config.toml key resolution helpers.
//! Owns supported-key normalization and flat global config loading.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::OnceLock;

use crate::config::types::ConfigKey;
use crate::io::config;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::DirectoryScope;
use crate::Result;

const LOCAL_STATE_ROOT_SUBJECT: &str = "local state root";

pub(crate) fn normalize_key(key: &str) -> Result<String> {
    Ok(ConfigKey::parse(key)?.canonical_name().to_string())
}

/// The value the global configuration holds for `key`, if it holds one.
///
/// The key a caller passes is whatever the operator typed, and it is normalized
/// here: which spellings the configuration accepts is settled in one place
/// rather than at every entry point that reads a value.
pub fn resolve_config_value(key: &str, base_dir: &Path) -> Result<Option<String>> {
    let normalized = normalize_key(key)?;
    let mut configured = load_global_config(base_dir)?;
    Ok(configured.remove(&normalized))
}

pub fn load_global_config(base_dir: &Path) -> Result<BTreeMap<String, String>> {
    let Some(home) = open_optional_home(base_dir)? else {
        return Ok(BTreeMap::new());
    };
    config::store::load_config_file_from_anchored_home(&home)
}

/// One command's lazily loaded global configuration.
/// The source stays bound to the home identity observed when the command began.
pub(crate) struct GlobalConfigSnapshot {
    home: Option<AnchoredDir>,
    values: OnceLock<BTreeMap<String, String>>,
}

impl GlobalConfigSnapshot {
    /// Bind a snapshot to an opened home or to its observed absence.
    pub(crate) fn for_home(home: Option<&AnchoredDir>) -> Self {
        Self {
            home: home.cloned(),
            values: OnceLock::new(),
        }
    }

    /// Load the configuration once through the fixed home identity.
    pub(crate) fn load(&self) -> Result<&BTreeMap<String, String>> {
        if let Some(values) = self.values.get() {
            return Ok(values);
        }
        let values = self
            .home
            .as_ref()
            .map(config::store::load_config_file_from_anchored_home)
            .transpose()?
            .unwrap_or_default();
        Ok(self.values.get_or_init(|| values))
    }
}

/// Open the local state home, reporting only its absence as "no configuration".
///
/// An unsafe path or an I/O failure keeps its own error: collapsing those into
/// an empty map would silently run the command with default settings.
pub(crate) fn open_optional_home(base_dir: &Path) -> Result<Option<AnchoredDir>> {
    AnchoredDir::open_optional(
        base_dir,
        DirectoryScope::LocalState,
        LOCAL_STATE_ROOT_SUBJECT,
    )
}

/// Open the local state home for writing, creating it when it is missing.
pub(crate) fn ensure_home(base_dir: &Path) -> Result<AnchoredDir> {
    AnchoredDir::ensure(
        base_dir,
        DirectoryScope::LocalState,
        LOCAL_STATE_ROOT_SUBJECT,
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/config_resolution_global_test.rs"]
mod config_resolution_global_test;
