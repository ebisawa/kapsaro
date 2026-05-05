// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH signing method resolution
//!
//! Resolves SSH signing method based on the following priority order:
//! 1. CLI option (--ssh-agent / --ssh-keygen)
//! 2. Environment variable (SECRETENV_SSH_SIGNING_METHOD)
//! 3. Global config (SECRETENV_HOME/config.toml)
//! 4. Default (auto)

use crate::config::types;
use crate::{Error, Result};
use std::path::Path;

use super::common::resolve_string_required;

/// Parse an SSH signing method config string.
pub(crate) fn parse_ssh_signing_method_config(s: &str) -> Result<types::SshSigningMethodConfig> {
    match s {
        "auto" => Ok(types::SshSigningMethodConfig::Auto),
        "ssh-agent" => Ok(types::SshSigningMethodConfig::SshAgent),
        "ssh-keygen" => Ok(types::SshSigningMethodConfig::SshKeygen),
        _ => Err(Error::InvalidArgument {
            message: format!(
                "Invalid signing method '{}'. Expected 'auto', 'ssh-agent', or 'ssh-keygen'",
                s
            ),
        }),
    }
}

/// Resolve SSH signing method config based on priority order.
///
/// # Priority Order
///
/// 1. `ssh_signing_method_opt` parameter (CLI option --ssh-agent / --ssh-keygen)
/// 2. `SECRETENV_SSH_SIGNING_METHOD` environment variable
/// 3. Global config (`SECRETENV_HOME/config.toml`)
/// 4. Default (auto)
pub(crate) fn resolve_ssh_signing_method_config(
    ssh_signing_method_opt: Option<types::SshSigningMethod>,
    base_dir: Option<&Path>,
) -> Result<types::SshSigningMethodConfig> {
    // Priority 1: CLI option (explicit SshSigningMethod → convert to Config)
    if let Some(signer) = ssh_signing_method_opt {
        return Ok(match signer {
            types::SshSigningMethod::SshAgent => types::SshSigningMethodConfig::SshAgent,
            types::SshSigningMethod::SshKeygen => types::SshSigningMethodConfig::SshKeygen,
        });
    }

    // Priority 2-4: env var / config / default (auto)
    let signing_method = resolve_string_required(
        None,
        Some("SECRETENV_SSH_SIGNING_METHOD"),
        "ssh_signing_method",
        base_dir,
        "auto".to_string(),
    )?;

    parse_ssh_signing_method_config(&signing_method)
}

/// Resolve SshSigningMethodConfig to a concrete SshSigningMethod.
///
/// For `Auto`, ssh-agent is preferred when an agent socket is available;
/// otherwise falls back to ssh-keygen.
pub(crate) fn resolve_ssh_signing_method(
    config: types::SshSigningMethodConfig,
) -> types::SshSigningMethod {
    match config {
        types::SshSigningMethodConfig::SshAgent => types::SshSigningMethod::SshAgent,
        types::SshSigningMethodConfig::SshKeygen => types::SshSigningMethod::SshKeygen,
        types::SshSigningMethodConfig::Auto => {
            if crate::io::ssh::agent::socket::is_agent_socket_available() {
                types::SshSigningMethod::SshAgent
            } else {
                types::SshSigningMethod::SshKeygen
            }
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/config_resolution_ssh_signing_method_test.rs"]
mod tests;
