// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Signature backend factory

use super::signature_backend::SignatureBackend;
use super::ssh_agent::SshAgentBackend;
use super::ssh_keygen::SshKeygenBackend;
use crate::config::types::SshSigner;
use crate::io::ssh::agent::client::DefaultAgentSigner;
use crate::io::ssh::external::traits::SshKeygen;
use crate::io::ssh::protocol::key_descriptor::SshKeyDescriptor;

/// Factory: create backend based on config
///
/// # Arguments
///
/// * `method` - Signing method from config (SshAgent or SshKeygen)
/// * `ssh_keygen` - Implementation of the `SshKeygen` trait (used only for SshKeygen method)
/// * `key_descriptor` - SSH key descriptor (private or public key, used only for SshKeygen method)
///
/// # Returns
///
/// Boxed SignatureBackend implementation
pub fn build_backend(
    method: SshSigner,
    ssh_keygen: Box<dyn SshKeygen>,
    key_descriptor: Option<SshKeyDescriptor>,
) -> crate::Result<Box<dyn SignatureBackend>> {
    match method {
        SshSigner::SshAgent => Ok(Box::new(SshAgentBackend::new(Box::new(DefaultAgentSigner)))),
        SshSigner::SshKeygen => {
            let key_descriptor = key_descriptor.ok_or_else(|| crate::Error::Config {
                message: "SSH key descriptor is required for ssh-keygen signing".to_string(),
            })?;
            Ok(Box::new(SshKeygenBackend::new(ssh_keygen, key_descriptor)))
        }
    }
}
