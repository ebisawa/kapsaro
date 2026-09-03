// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Signature backend factory

use super::signature_backend::SignatureBackend;
use super::ssh_agent::SshAgentBackend;
use super::ssh_keygen::SshKeygenBackend;
use crate::config::types::SshSigningMethod;
use crate::io::ssh::agent::client::DefaultAgentSigner;
use crate::io::ssh::external::traits::SshKeygen;
use crate::io::ssh::protocol::key_descriptor::SshKeyDescriptor;
use std::path::PathBuf;

/// Factory: create backend based on config
///
/// # Arguments
///
/// * `method` - Signing method from config (SshAgent or SshKeygen)
/// * `ssh_keygen` - Implementation of the `SshKeygen` trait (used only for SshKeygen method)
/// * `key_descriptor` - SSH key descriptor (private or public key, used only for SshKeygen method)
/// * `agent_socket` - Caller-fixed agent socket (required for SshAgent method)
///
/// # Returns
///
/// Boxed SignatureBackend implementation
pub fn build_backend(
    method: SshSigningMethod,
    ssh_keygen: Box<dyn SshKeygen>,
    key_descriptor: Option<SshKeyDescriptor>,
    agent_socket: Option<PathBuf>,
) -> crate::Result<Box<dyn SignatureBackend>> {
    match method {
        SshSigningMethod::SshAgent => agent_socket
            .map(DefaultAgentSigner::new)
            .map(|signer| {
                Box::new(SshAgentBackend::new(Box::new(signer))) as Box<dyn SignatureBackend>
            })
            .ok_or_else(|| {
                crate::Error::build_config_error(
                    "SSH agent socket is required for ssh-agent signing".to_string(),
                )
            }),
        SshSigningMethod::SshKeygen => {
            let key_descriptor = key_descriptor.ok_or_else(|| {
                crate::Error::build_config_error(
                    "SSH key descriptor is required for ssh-keygen signing".to_string(),
                )
            })?;
            Ok(Box::new(SshKeygenBackend::new(ssh_keygen, key_descriptor)))
        }
    }
}
