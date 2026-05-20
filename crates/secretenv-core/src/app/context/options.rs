// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use crate::config::resolution::allow_expired_key::resolve_allow_expired_key;
use crate::config::types::SshSigningMethod;
use crate::io::config::paths::get_base_dir;
use crate::io::keystore::resolver::KeystoreResolver;
use crate::Result;

/// App-facing copy of common CLI options used by orchestration code.
#[derive(Debug, Clone)]
pub struct CommonCommandOptions {
    pub home: Option<PathBuf>,
    pub identity: Option<PathBuf>,
    pub debug: bool,
    pub verbose: bool,
    pub workspace: Option<PathBuf>,
    pub ssh_signing_method: Option<SshSigningMethod>,
    pub allow_expired_key: bool,
}

pub fn resolve_allow_expired_key_option(
    cli_value: Option<bool>,
    options: &CommonCommandOptions,
) -> Result<bool> {
    resolve_allow_expired_key(cli_value, options.home.as_deref())
}

impl CommonCommandOptions {
    /// Resolve base directory from options, environment, or defaults.
    pub fn resolve_base_dir(&self) -> Result<PathBuf> {
        match &self.home {
            Some(path) => Ok(path.clone()),
            None => get_base_dir(),
        }
    }

    /// Resolve keystore root from options or defaults.
    pub fn resolve_keystore_root(&self) -> Result<PathBuf> {
        KeystoreResolver::resolve(self.home.as_ref())
    }
}
