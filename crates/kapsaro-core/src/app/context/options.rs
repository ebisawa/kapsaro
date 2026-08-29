// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Common command options shared across app-layer orchestration code.
//! Bundles CLI-derived paths and flags and resolves them into base dir, keystore root, and operation options.

use std::cell::OnceCell;
use std::path::PathBuf;

use crate::api::operation::OperationOptions;
use crate::config::resolution::allow_expired_key::resolve_allow_expired_key;
use crate::config::resolution::allow_non_member::resolve_allow_non_member;
use crate::config::resolution::global::{create_home, open_optional_home, GlobalConfigSnapshot};
use crate::config::types::SshSigningMethod;
use crate::io::config::paths::get_base_dir;
use crate::io::keystore::resolver::KeystoreResolver;
use crate::support::fs::anchor::AnchoredDir;
use crate::{Error, Result};

/// App-facing copy of common CLI options used by orchestration code.
///
/// The local state root is fixed the first time anything is asked of it and
/// every later answer comes from that one directory, so the options are built
/// through [`CommonCommandOptions::new`] rather than assembled field by field.
#[derive(Debug, Clone, Default)]
pub struct CommonCommandOptions {
    pub home: Option<PathBuf>,
    pub identity: Option<PathBuf>,
    pub verbose: bool,
    pub workspace: Option<PathBuf>,
    pub ssh_signing_method: Option<SshSigningMethod>,
    pub allow_expired_key: bool,
    pub allow_non_member: bool,
    /// Local state root this command works through, and the configuration read
    /// through it. Opened on first use and kept for the rest of the command.
    local_state: OnceCell<CommandLocalState>,
}

/// The local state root one command fixed, with its configuration.
#[derive(Debug, Clone)]
struct CommandLocalState {
    home: Option<AnchoredDir>,
    config: GlobalConfigSnapshot,
}

/// The trust allowances a read command settles before it resolves anything else.
#[derive(Debug, Clone, Copy)]
pub struct ReadTrustAllowances {
    pub allow_expired_key: bool,
    pub allow_non_member: bool,
}

pub fn resolve_allow_expired_key_option(
    cli_value: Option<bool>,
    options: &CommonCommandOptions,
) -> Result<bool> {
    resolve_allow_expired_key(cli_value, options.global_config()?)
}

/// Resolve both read-trust allowances against one reading of the configuration.
///
/// The two settings sit in the same file, so a command that needs both takes one
/// snapshot rather than opening and parsing the local state root twice over.
pub fn resolve_read_trust_allowances(
    cli_allow_expired_key: Option<bool>,
    cli_allow_non_member: Option<bool>,
    options: &CommonCommandOptions,
) -> Result<ReadTrustAllowances> {
    let config = options.global_config()?;
    Ok(ReadTrustAllowances {
        allow_expired_key: resolve_allow_expired_key(cli_allow_expired_key, config)?,
        allow_non_member: resolve_allow_non_member(cli_allow_non_member, config)?,
    })
}

impl CommonCommandOptions {
    /// Options for a command invoked with none of them named.
    pub fn new() -> Self {
        Self::default()
    }

    /// Select the local state root the command was told to work under.
    pub fn with_home(mut self, home: Option<PathBuf>) -> Self {
        self.home = home;
        self
    }

    /// Select the SSH identity file the command was told to sign with.
    pub fn with_identity(mut self, identity: Option<PathBuf>) -> Self {
        self.identity = identity;
        self
    }

    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Select the workspace the command was told to act on.
    pub fn with_workspace(mut self, workspace: Option<PathBuf>) -> Self {
        self.workspace = workspace;
        self
    }

    pub fn with_ssh_signing_method(mut self, method: Option<SshSigningMethod>) -> Self {
        self.ssh_signing_method = method;
        self
    }

    /// Resolve base directory from options, environment, or defaults.
    pub fn resolve_base_dir(&self) -> Result<PathBuf> {
        match &self.home {
            Some(path) => Ok(path.clone()),
            None => get_base_dir(),
        }
    }

    /// The local state root this command works through, opened on first use.
    ///
    /// The relaxation settings, the workspace, the keystore and the trust store
    /// are all answered from here, and a root repointed while the command runs
    /// would otherwise let one of them come from one tree and the next from
    /// another. The root is opened rather than created: a command that only
    /// reads must not bring local state into existence.
    ///
    /// A root that cannot even be named is answered as absence rather than as a
    /// failure. Naming it takes an environment that a command working only from
    /// an explicit workspace never needs, and the commands that do need a root
    /// reach for it by name of their own and report what is missing there.
    fn local_state(&self) -> Result<&CommandLocalState> {
        if let Some(local_state) = self.local_state.get() {
            return Ok(local_state);
        }
        let home = match self.resolve_base_dir() {
            Ok(base_dir) => open_optional_home(&base_dir)?,
            Err(_) => None,
        };
        let config = GlobalConfigSnapshot::for_home(home.as_ref());
        Ok(self
            .local_state
            .get_or_init(|| CommandLocalState { home, config }))
    }

    /// The local state root this command fixed, when it has one at all.
    pub(crate) fn fixed_home(&self) -> Result<Option<&AnchoredDir>> {
        Ok(self.local_state()?.home.as_ref())
    }

    /// Ensure and fix the local state root a writing command will use.
    ///
    /// A root already observed as absent is not created later through the same
    /// options. That observation is a command snapshot, and replacing it with a
    /// newly created directory would make earlier configuration and later
    /// writes refer to different identities.
    pub(crate) fn ensure_local_state_home(&self) -> Result<&AnchoredDir> {
        if let Some(local_state) = self.local_state.get() {
            return local_state.home.as_ref().ok_or_else(|| {
                Error::build_invalid_operation_error(
                    "Local state home was already fixed as absent; restart the command to create it"
                        .to_string(),
                )
            });
        }
        let home = create_home(&self.resolve_base_dir()?)?;
        let config = GlobalConfigSnapshot::for_home(Some(&home));
        self.local_state
            .set(CommandLocalState {
                home: Some(home),
                config,
            })
            .map_err(|_| {
                Error::build_invalid_operation_error(
                    "Local state home changed while the command was fixing it".to_string(),
                )
            })?;
        Ok(self
            .local_state
            .get()
            .and_then(|state| state.home.as_ref())
            .expect("ensured local state must contain an opened home"))
    }

    /// The global configuration this command resolves its settings from.
    ///
    /// The snapshot reads the file at most once and reads it through the root
    /// this command fixed, so every setting a command resolves comes from the
    /// same directory.
    pub(crate) fn global_config(&self) -> Result<&GlobalConfigSnapshot> {
        Ok(&self.local_state()?.config)
    }

    /// Resolve keystore root from options or defaults.
    pub fn resolve_keystore_root(&self) -> Result<PathBuf> {
        KeystoreResolver::resolve(self.home.as_ref())
    }

    /// Build non-secret facade operation options for verification and crypto paths.
    pub fn operation_options(&self) -> OperationOptions {
        OperationOptions::new().with_allow_expired_key(self.allow_expired_key)
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_context_options_test.rs"]
mod tests;
