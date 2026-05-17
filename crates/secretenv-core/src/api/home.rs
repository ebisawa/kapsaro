// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SecretEnv home facade.

use std::path::{Path, PathBuf};

use crate::io::keystore::paths::get_keystore_root_from_base;

use super::key::LocalKeyStore;
use super::trust::LocalTrustStore;

/// Explicit SecretEnv home directory.
#[derive(Debug, Clone)]
pub struct SecretEnvHome {
    base_dir: PathBuf,
}

impl SecretEnvHome {
    /// Open a SecretEnv home directory. The path is not read from the environment.
    pub fn open(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    /// Return the base directory.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Return a facade for `<SECRETENV_HOME>/keys`.
    pub fn key_store(&self) -> LocalKeyStore {
        LocalKeyStore::new(get_keystore_root_from_base(&self.base_dir))
    }

    /// Return a facade for `<SECRETENV_HOME>/trust`.
    pub fn trust_store(&self, owner_handle: impl Into<String>) -> LocalTrustStore {
        LocalTrustStore::new(self.base_dir.clone(), owner_handle.into())
    }
}
