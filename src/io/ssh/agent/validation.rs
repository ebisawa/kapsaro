// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH agent validation utilities

use crate::io::ssh::SshError;
use crate::support::path::display_path_relative_to_cwd;
use crate::Result;
use ssh_key::PublicKey;

/// Validate that the agent has at least one key loaded
pub fn validate_agent_has_keys(
    client: &mut ssh_agent_client_rs::Client,
    socket_path: &std::path::Path,
) -> Result<()> {
    let identities = client.list_all_identities().map_err(|e| {
        crate::Error::from(SshError::operation_failed_with_source(
            format!("ssh-agent list identities failed: {}", e),
            e,
        ))
    })?;

    let total = identities.len();

    // If the agent is reachable but has no identities, signing will always fail.
    // Fail fast with a more actionable error than the agent's generic "Failure".
    if total == 0 {
        let socket_display = display_path_relative_to_cwd(socket_path);
        return Err(SshError::operation_failed(format!(
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
pub fn find_key_in_agent(
    identities: &[ssh_agent_client_rs::Identity],
    public_key: &PublicKey,
) -> Result<bool> {
    for ident in identities {
        match ident {
            ssh_agent_client_rs::Identity::PublicKey(pk) => {
                if pk.as_ref().as_ref().key_data() == public_key.key_data() {
                    return Ok(true);
                }
            }
            ssh_agent_client_rs::Identity::Certificate(_cert) => {}
        }
    }
    Ok(false)
}

/// Validate that the agent has the requested key and provide helpful error message
pub fn validate_key_present(target_key_present: bool, socket_path: &std::path::Path) -> Result<()> {
    if !target_key_present {
        let socket_display = display_path_relative_to_cwd(socket_path);
        return Err(SshError::operation_failed(format!(
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
