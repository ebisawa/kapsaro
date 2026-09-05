// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Resolved configuration operations shared by API callers.

use crate::config::resolution::global;
use crate::io::config::store::{config_key_not_found, set_config_value, unset_config_value};
use crate::io::keystore::access::{build_missing_keystore_error, KeystoreAccess};
use crate::io::keystore::paths::get_keystore_root_from_base;
use crate::model::identity::MemberHandle;
use crate::service::key::LocalKeyStore;
use crate::support::fs::anchor::AnchoredDir;
use crate::Result;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// One command's fixed local-state home and configuration snapshot.
pub struct LocalStateSession {
    base_dir: PathBuf,
    home: OnceLock<AnchoredDir>,
    config: global::GlobalConfigSnapshot,
}

impl LocalStateSession {
    /// Open an explicit local-state root without parsing its configuration.
    pub fn open(base_dir: impl Into<PathBuf>) -> Result<Self> {
        let base_dir = base_dir.into();
        let opened_home = global::open_optional_home(&base_dir)?;
        let config = global::GlobalConfigSnapshot::for_home(opened_home.as_ref());
        let home = OnceLock::new();
        if let Some(opened_home) = opened_home {
            let _ = home.set(opened_home);
        }
        Ok(Self {
            base_dir,
            home,
            config,
        })
    }

    /// Return the logical path used only for display and explicit child paths.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Load the configuration on first access through the fixed home.
    pub fn load_config(&self) -> Result<&BTreeMap<String, String>> {
        self.config.load()
    }

    /// Open the keystore through the same home used for configuration.
    pub fn open_optional_key_store(&self) -> Result<Option<LocalKeyStore>> {
        self.home
            .get()
            .map(KeystoreAccess::open_optional_from_anchored_home)
            .transpose()
            .map(Option::flatten)
            .map(|access| access.map(LocalKeyStore::from_access))
    }

    /// Require a keystore through the same fixed home.
    pub fn require_key_store(&self, owner: &MemberHandle) -> Result<LocalKeyStore> {
        let home = self.home.get().ok_or_else(|| {
            build_missing_keystore_error(&get_keystore_root_from_base(&self.base_dir), owner)
        })?;
        KeystoreAccess::open_from_anchored_home_required(home, owner)
            .map(LocalKeyStore::from_access)
    }

    pub(crate) fn home(&self) -> Option<&AnchoredDir> {
        self.home.get()
    }

    pub(crate) fn ensured_home(&self) -> Result<&AnchoredDir> {
        if self.home.get().is_none() {
            let opened = global::ensure_home(&self.base_dir)?;
            let _ = self.home.set(opened);
        }
        Ok(self
            .home
            .get()
            .expect("local-state home is fixed after successful creation"))
    }
}

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

pub fn resolve_config_value(base_dir: &std::path::Path, key: &str) -> Result<String> {
    global::resolve_config_value(key, base_dir)?.ok_or_else(|| config_key_not_found(key))
}

pub fn list_config(base_dir: &std::path::Path) -> Result<BTreeMap<String, String>> {
    global::load_global_config(base_dir)
}

pub fn set_config(base_dir: &std::path::Path, key: &str, value: &str) -> Result<ConfigSetResult> {
    let normalized = global::normalize_key(key)?;
    let home = global::ensure_home(base_dir)?;
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
pub fn unset_config(key: &str, base_dir: &std::path::Path) -> Result<ConfigUnsetResult> {
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
#[path = "../../tests/unit/internal/service_config_test.rs"]
mod service_config_test;
