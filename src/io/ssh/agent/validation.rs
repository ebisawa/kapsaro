// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH agent validation utilities

use crate::io::ssh::SshError;
use crate::support::path::format_path_relative_to_cwd;
use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentity {
    key_blob: Vec<u8>,
    comment: String,
}

impl AgentIdentity {
    pub fn new(key_blob: Vec<u8>, comment: String) -> Self {
        Self { key_blob, comment }
    }

    pub fn key_blob(&self) -> &[u8] {
        &self.key_blob
    }

    #[allow(dead_code)]
    pub fn comment(&self) -> &str {
        &self.comment
    }
}

/// Validate that the agent has at least one key loaded
pub fn validate_agent_has_keys(
    identities: &[AgentIdentity],
    socket_path: &std::path::Path,
) -> Result<()> {
    // If the agent is reachable but has no identities, signing will always fail.
    // Fail fast with a more actionable error than the agent's generic "Failure".
    if identities.is_empty() {
        let socket_display = format_path_relative_to_cwd(socket_path);
        return Err(SshError::build_operation_failed_error(format!(
            "ssh-agent is reachable but has no keys loaded.\n\
Agent socket: {}\n\
Check loaded keys: SSH_AUTH_SOCK=\"{}\" ssh-add -l\n\
If empty, ensure your SSH agent (e.g., 1Password) has keys available.\n\
Note: This agent socket was resolved from ~/.ssh/config IdentityAgent or SSH_AUTH_SOCK.",
            socket_display, socket_display
        ))
        .into());
    }

    Ok(())
}

/// Find if the target public key is present in the agent
///
/// Compares key data only, ignoring comments which may differ between
/// the local .pub file and the agent's stored identity.
pub fn find_key_in_agent(identities: &[AgentIdentity], public_key_blob: &[u8]) -> Result<bool> {
    Ok(identities
        .iter()
        .any(|identity| identity.key_blob() == public_key_blob))
}

/// Validate that the agent has the requested key and provide helpful error message
pub fn validate_key_present(target_key_present: bool, socket_path: &std::path::Path) -> Result<()> {
    if !target_key_present {
        let socket_display = format_path_relative_to_cwd(socket_path);
        return Err(SshError::build_operation_failed_error(format!(
            "ssh-agent does not have the requested SSH public key loaded.\n\
Agent socket: {}\n\
Check available keys: SSH_AUTH_SOCK=\"{}\" ssh-add -L\n\
The requested key must match one of the keys listed by ssh-add -L.\n\
Alternative: Set config 'ssh_signing_method: ssh-keygen'",
            socket_display, socket_display
        ))
        .into());
    }
    Ok(())
}
