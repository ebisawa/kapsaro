// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH agent socket path resolution

use crate::io::ssh::openssh_config::find_identity_agent;
use crate::io::ssh::SshError;
use crate::Result;
use std::env;
use std::path::PathBuf;

/// Resolve ssh-agent socket path from SSH config or environment
///
/// # Priority (config_first)
///
/// 1. `~/.ssh/config` `IdentityAgent` (if present and not "none")
/// 2. `SSH_AUTH_SOCK` environment variable
/// 3. Error if neither is available
///
/// # Returns
///
/// Socket path, or error if not found
pub fn resolve_agent_socket_path() -> Result<PathBuf> {
    // Priority 1: Check ~/.ssh/config for IdentityAgent
    if let Some(config_path) = find_identity_agent()? {
        return Ok(config_path);
    }

    // Priority 2: Fall back to SSH_AUTH_SOCK
    let socket_path = env::var("SSH_AUTH_SOCK").map_err(|_| {
        crate::Error::from(SshError::build_operation_failed_error(
            "SSH_AUTH_SOCK not set and no IdentityAgent found in ~/.ssh/config",
        ))
    })?;

    Ok(PathBuf::from(socket_path))
}

/// Check if ssh-agent socket is available (without connecting)
///
/// Returns true if `SSH_AUTH_SOCK` or `IdentityAgent` is configured.
/// Does not verify the socket is functional.
pub fn is_agent_socket_available() -> bool {
    resolve_agent_socket_path().is_ok()
}
