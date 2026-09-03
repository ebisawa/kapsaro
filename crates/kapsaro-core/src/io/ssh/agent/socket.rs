// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH agent socket path resolution

use crate::io::ssh::openssh_config::find_identity_agent;
use crate::Result;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Resolve ssh-agent socket path from caller-fixed SSH config inputs.
///
/// # Priority (config_first)
///
/// 1. `~/.ssh/config` `IdentityAgent` (if present and not "none")
/// 2. Caller-fixed `SSH_AUTH_SOCK` value
/// 3. `None` if neither is available
///
/// # Returns
///
/// Socket path, or `None` if no input selects one.
pub fn resolve_agent_socket_path(
    home: Option<&Path>,
    ssh_auth_sock: Option<PathBuf>,
    expansion_values: &BTreeMap<String, String>,
) -> Result<Option<PathBuf>> {
    if let Some(home) = home {
        if let Some(config_path) = find_identity_agent(home, expansion_values)? {
            return Ok(Some(config_path));
        }
    }
    Ok(ssh_auth_sock)
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/ssh_agent_socket_test.rs"]
mod ssh_agent_socket_test;
