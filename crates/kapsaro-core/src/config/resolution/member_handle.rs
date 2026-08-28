// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Member handle resolution
//!
//! Resolves the member handle based on the following priority order:
//! 1. CLI argument (--member-handle)
//! 2. Environment variable (KAPSARO_MEMBER_HANDLE)
//! 3. Global config (KAPSARO_HOME/config.toml)
//! 4. Single member entry in keystore

use crate::config::resolution::global::GlobalConfigSnapshot;
#[cfg(test)]
use crate::io::config as io_config;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::keystore::member::load_single_member_handle_from_keystore;
use crate::model::identity::MemberHandle;
#[cfg(test)]
use crate::ErrorKind;
use crate::Result;

#[cfg(test)]
use std::path::Path;

use super::common::resolve_string_from_sources;
use crate::config::types::ConfigKey;

const ENV_VAR: &str = "KAPSARO_MEMBER_HANDLE";

/// Where the resolver reads the configured handle and the keystore fallback.
///
/// The two sources are named apart because they answer different questions: one
/// holds `config.toml`, the other holds the keys a single-member keystore is
/// read from. Configuration always arrives as the snapshot the command already
/// took, so the file behind it is read once however many settings are resolved.
pub(crate) struct MemberHandleResolver<'a> {
    config: &'a GlobalConfigSnapshot,
    keystore: MemberKeystoreSource<'a>,
}

/// Where the single-member fallback reads the keystore from.
#[derive(Clone, Copy)]
enum MemberKeystoreSource<'a> {
    /// Open the keystore under a base directory when the fallback is reached.
    #[cfg(test)]
    BaseDirectory(Option<&'a Path>),
    /// A keystore the caller already opened, or none to fall back to.
    Opened(Option<&'a KeystoreAccess>),
}

impl<'a> MemberHandleResolver<'a> {
    pub(crate) fn fixed(
        config: &'a GlobalConfigSnapshot,
        keystore: Option<&'a KeystoreAccess>,
    ) -> Self {
        Self {
            config,
            keystore: MemberKeystoreSource::Opened(keystore),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_base_dir(
        config: &'a GlobalConfigSnapshot,
        base_dir: Option<&'a Path>,
    ) -> Self {
        Self {
            config,
            keystore: MemberKeystoreSource::BaseDirectory(base_dir),
        }
    }

    pub(crate) fn resolve(
        &self,
        member_handle_opt: Option<String>,
    ) -> Result<Option<MemberHandle>> {
        if let Some(member_handle) = self.resolve_explicit_source(member_handle_opt)? {
            return MemberHandle::try_from(member_handle).map(Some);
        }

        self.resolve_keystore_fallback()
    }

    fn resolve_explicit_source(&self, cli_value: Option<String>) -> Result<Option<String>> {
        resolve_string_from_sources(cli_value, Some(ENV_VAR), None, || {
            self.config.get(ConfigKey::MemberHandle.canonical_name())
        })
        .map(|resolved| resolved.map(|(value, _)| value))
    }

    fn resolve_keystore_fallback(&self) -> Result<Option<MemberHandle>> {
        match self.keystore {
            #[cfg(test)]
            MemberKeystoreSource::BaseDirectory(base_dir) => {
                resolve_optional_member_handle_from_keystore(base_dir)
            }
            MemberKeystoreSource::Opened(keystore) => keystore
                .map(load_single_member_handle_from_keystore)
                .transpose()
                .map(Option::flatten),
        }
    }
}

/// Resolve the member handle from non-interactive sources and return `None` when unresolved.
#[cfg(test)]
pub(crate) fn resolve_member_handle_with_fallback(
    member_handle_opt: Option<String>,
    base_dir: Option<&Path>,
) -> Result<Option<String>> {
    let config = GlobalConfigSnapshot::for_base_dir(base_dir);
    MemberHandleResolver::from_base_dir(&config, base_dir)
        .resolve(member_handle_opt)
        .map(|member| member.map(MemberHandle::into_string))
}

#[cfg(test)]
fn resolve_optional_member_handle_from_keystore(
    base_dir: Option<&Path>,
) -> Result<Option<MemberHandle>> {
    let base_dir = match base_dir {
        Some(dir) => dir.to_path_buf(),
        None => io_config::paths::get_base_dir()?,
    };

    let access = match KeystoreAccess::open_from_home(&base_dir) {
        Ok(access) => access,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    load_single_member_handle_from_keystore(&access)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/config_resolution_member_handle_test.rs"]
mod config_resolution_member_handle_test;
