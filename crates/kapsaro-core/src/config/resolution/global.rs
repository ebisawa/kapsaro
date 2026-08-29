// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Global config.toml key resolution helpers.
//! Owns supported-key normalization and flat global config loading.

use std::cell::OnceCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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
pub fn resolve_config_value(key: &str, base_dir: Option<&Path>) -> Result<Option<String>> {
    let normalized = normalize_key(key)?;
    let mut configured = load_global_config(base_dir)?;
    Ok(configured.remove(&normalized))
}

pub fn load_global_config(base_dir: Option<&Path>) -> Result<BTreeMap<String, String>> {
    let base_dir = match base_dir {
        Some(dir) => dir.to_path_buf(),
        None => config::paths::get_base_dir()?,
    };
    let Some(home) = open_optional_home(&base_dir)? else {
        return Ok(BTreeMap::new());
    };
    config::store::load_config_file_from_anchored_home(&home)
}

/// The global `config.toml` one command resolves its settings from.
///
/// Opening the local state root walks its ancestors for safety and parsing the
/// file rebuilds the same map, while a single command asks for several settings.
/// The file is therefore read once here and every later lookup answers from what
/// was read. Nothing is read until a lookup reaches configuration at all, so a
/// setting that arrives on the command line or in the environment still costs
/// nothing, and a command that never falls through never opens the file.
///
/// Once read, a snapshot is fixed for its lifetime: `values` is a `OnceCell`
/// with no invalidation API, so nothing here notices `config.toml` changing
/// underneath it. A command that writes the config file must not hold one
/// snapshot across that write and keep reading from it afterward; it would
/// keep answering with the content read before the write.
#[derive(Debug, Clone)]
pub(crate) struct GlobalConfigSnapshot {
    source: GlobalConfigSource,
    values: OnceCell<BTreeMap<String, String>>,
}

/// Where a snapshot reads its configuration from.
#[derive(Debug, Clone)]
enum GlobalConfigSource {
    /// The local state root under a base directory, or under the default one.
    BaseDirectory(Option<PathBuf>),
    /// A local state root the caller already opened, skipping the ancestor walk.
    Home(AnchoredDir),
    /// The command has no local state root, so nothing is configured.
    Absent,
}

impl GlobalConfigSnapshot {
    /// Read the configuration of the local state root under `base_dir`.
    pub(crate) fn for_base_dir(base_dir: Option<&Path>) -> Self {
        Self::from_source(GlobalConfigSource::BaseDirectory(
            base_dir.map(Path::to_path_buf),
        ))
    }

    /// Read the configuration of a local state root the caller already opened.
    pub(crate) fn for_home(home: Option<&AnchoredDir>) -> Self {
        Self::from_source(match home {
            Some(home) => GlobalConfigSource::Home(home.clone()),
            None => GlobalConfigSource::Absent,
        })
    }

    fn from_source(source: GlobalConfigSource) -> Self {
        Self {
            source,
            values: OnceCell::new(),
        }
    }

    /// Every configured key, reading the file on the first call and no later one.
    pub(crate) fn values(&self) -> Result<&BTreeMap<String, String>> {
        if let Some(values) = self.values.get() {
            return Ok(values);
        }
        let loaded = self.source.load()?;
        Ok(self.values.get_or_init(|| loaded))
    }

    /// The value configured for `key`, if the file holds one.
    pub(crate) fn get(&self, key: &str) -> Result<Option<String>> {
        Ok(self.values()?.get(key).cloned())
    }
}

impl GlobalConfigSource {
    fn load(&self) -> Result<BTreeMap<String, String>> {
        match self {
            Self::BaseDirectory(base_dir) => load_global_config(base_dir.as_deref()),
            Self::Home(home) => config::store::load_config_file_from_anchored_home(home),
            Self::Absent => Ok(BTreeMap::new()),
        }
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
pub(crate) fn create_home(base_dir: &Path) -> Result<AnchoredDir> {
    AnchoredDir::create(
        base_dir,
        DirectoryScope::LocalState,
        LOCAL_STATE_ROOT_SUBJECT,
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_config_test.rs"]
mod feature_config_test;
