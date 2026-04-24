// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH Key resolution
//!
//! Resolves SSH key path based on the following priority order:
//! 1. CLI option (-i / --ssh-identity)
//! 2. Environment variable (SECRETENV_SSH_IDENTITY)
//! 3. Global config (SECRETENV_HOME/config.toml)
//! 4. Default (~/.ssh/id_ed25519)

use crate::io::ssh::protocol::SshKeyDescriptor;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

use super::common::{
    expand_tilde, get_default_ssh_key_path, resolve_string_with_source, StringSourceResolution,
};

/// Source of SSH key configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SshKeySource {
    /// CLI option (-i / --ssh-identity)
    Cli,
    /// Environment variable (SECRETENV_SSH_IDENTITY)
    Env,
    /// Global config (SECRETENV_HOME/config.toml)
    GlobalConfig,
    /// Default path (~/.ssh/id_ed25519)
    Default,
}

/// SSH key resolution
#[derive(Debug, Clone)]
pub(crate) struct SshKeyResolution {
    /// Path
    pub(crate) path: PathBuf,
    /// Source of the configuration
    pub(crate) source: SshKeySource,
    /// Whether the file exists
    pub(crate) exists: bool,
}

/// Resolve SSH key candidate with source and existence information
///
/// This function returns a candidate even if the file doesn't exist,
/// allowing callers to make decisions based on the source and existence.
///
/// # Priority Order
///
/// 1. `ssh_key_opt` parameter (CLI option -i / --ssh-identity)
/// 2. `SECRETENV_SSH_IDENTITY` environment variable
/// 3. Global config (`SECRETENV_HOME/config.toml`)
/// 4. Default path (`~/.ssh/id_ed25519`)
pub(crate) fn resolve_ssh_key_candidate(
    ssh_key_opt: Option<PathBuf>,
    base_dir: Option<&Path>,
) -> Result<SshKeyResolution> {
    if let Some(ssh_key) = ssh_key_opt {
        return Ok(build_ssh_key_resolution(ssh_key, SshKeySource::Cli));
    }

    if let Some(candidate) = resolve_configured_ssh_key_candidate(base_dir)? {
        return Ok(candidate);
    }

    Ok(build_ssh_key_resolution(
        get_default_ssh_key_path()?,
        SshKeySource::Default,
    ))
}

pub(crate) fn build_ssh_key_not_found_error(candidate: &SshKeyResolution) -> Error {
    if !candidate.exists {
        let source_str = match candidate.source {
            SshKeySource::Cli => "CLI option",
            SshKeySource::Env => "SECRETENV_SSH_IDENTITY",
            SshKeySource::GlobalConfig => "global config",
            SshKeySource::Default => {
                return Error::NotFound {
                    message:
                        "SSH key not configured and default path (~/.ssh/id_ed25519) not found"
                            .to_string(),
                };
            }
        };
        return Error::NotFound {
            message: format!(
                "SSH key file from {} does not exist: {}",
                source_str,
                format_path_relative_to_cwd(&candidate.path)
            ),
        };
    }
    unreachable!("build_ssh_key_not_found_error requires a missing candidate")
}

/// Resolve SSH key descriptor with automatic key type detection
///
/// This function resolves the SSH key candidate using the configured priority order,
/// requires the selected file to exist, then automatically detects whether the
/// key is a private key or a public key (.pub file).
///
/// # Priority Order
///
/// 1. `ssh_key_opt` parameter (CLI option -i / --ssh-identity)
/// 2. `SECRETENV_SSH_IDENTITY` environment variable
/// 3. Global config (`SECRETENV_HOME/config.toml`)
/// 4. Default path (`~/.ssh/id_ed25519`)
///
/// # Key Type Detection
///
/// Files ending with `.pub` extension are treated as public keys.
/// All other files are treated as private keys.
pub(crate) fn resolve_ssh_key_descriptor(
    ssh_key_opt: Option<PathBuf>,
    base_dir: Option<&Path>,
) -> Result<SshKeyDescriptor> {
    let candidate = resolve_ssh_key_candidate(ssh_key_opt, base_dir)?;
    if !candidate.exists {
        return Err(build_ssh_key_not_found_error(&candidate));
    }
    Ok(SshKeyDescriptor::from_path(candidate.path))
}

fn resolve_configured_ssh_key_candidate(
    base_dir: Option<&Path>,
) -> Result<Option<SshKeyResolution>> {
    resolve_string_with_source(
        None,
        Some("SECRETENV_SSH_IDENTITY"),
        "ssh_identity",
        base_dir,
        None,
    )?
    .map(build_candidate_from_source)
    .transpose()
}

fn build_candidate_from_source(
    (path, source): (String, StringSourceResolution),
) -> Result<SshKeyResolution> {
    match source {
        StringSourceResolution::Env => Ok(build_ssh_key_resolution(
            PathBuf::from(path),
            SshKeySource::Env,
        )),
        StringSourceResolution::GlobalConfig => Ok(build_ssh_key_resolution(
            expand_tilde(&path)?,
            SshKeySource::GlobalConfig,
        )),
        _ => unreachable!("unexpected SSH key source"),
    }
}

fn build_ssh_key_resolution(path: PathBuf, source: SshKeySource) -> SshKeyResolution {
    SshKeyResolution {
        exists: path.exists(),
        path,
        source,
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/config_resolution_ssh_key_test.rs"]
mod tests;
