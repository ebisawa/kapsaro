// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Keystore root resolution.
//!
//! Provides unified keystore root resolution logic to avoid duplication
//! across feature and CLI layers.

use crate::io::config::paths::get_base_dir;
use crate::io::keystore::paths::get_keystore_root_from_base;
use crate::Result;
use std::path::PathBuf;

/// Resolver for keystore root paths.
pub struct KeystoreResolver;

impl KeystoreResolver {
    /// Resolve keystore root from home override or default.
    ///
    /// # Arguments
    /// * `home` - Optional home directory override (if None, uses default from config)
    ///
    /// # Returns
    /// Path to keystore root directory (base_dir/keys)
    pub fn resolve(home: Option<&PathBuf>) -> Result<PathBuf> {
        let keystore_root = match home {
            Some(path) => get_keystore_root_from_base(path),
            None => {
                let base = get_base_dir()?;
                get_keystore_root_from_base(&base)
            }
        };
        Ok(keystore_root)
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_keystore_resolver_test.rs"]
mod io_keystore_resolver_test;
