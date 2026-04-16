// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH keygen backend implementation

use super::signature_backend::SignatureBackend;
use crate::io::ssh::external::traits::SshKeygen;
use crate::io::ssh::protocol::key_descriptor::SshKeyDescriptor;
use crate::io::ssh::protocol::types::Ed25519RawSignature;
use crate::Result;

/// ssh-keygen backend (Method B)
///
/// Invokes `ssh-keygen -Y sign` via the `SshKeygen` trait.
/// Requires:
/// - OpenSSH 8.0+ with `-Y sign` support
/// - Key file (private or public key):
///   - Private key: signs directly with the key file
///   - Public key: uses ssh-agent for signing (key must be loaded)
pub struct SshKeygenBackend {
    ssh_keygen: Box<dyn SshKeygen>,
    key_descriptor: SshKeyDescriptor,
}

impl SshKeygenBackend {
    /// Create a new ssh-keygen backend
    ///
    /// # Arguments
    ///
    /// * `ssh_keygen` - Implementation of the `SshKeygen` trait
    /// * `key_descriptor` - SSH key descriptor (private or public key)
    ///
    /// # Note
    ///
    /// Both private and public keys are supported:
    /// - Private key: ssh-keygen signs directly with the key file
    /// - Public key: ssh-keygen uses ssh-agent for signing (key must be loaded in agent)
    pub fn new(ssh_keygen: Box<dyn SshKeygen>, key_descriptor: SshKeyDescriptor) -> Self {
        Self {
            ssh_keygen,
            key_descriptor,
        }
    }
}

impl SignatureBackend for SshKeygenBackend {
    fn sign_sshsig(
        &self,
        namespace: &str,
        _ssh_pubkey: &str,
        message: &[u8],
    ) -> Result<Ed25519RawSignature> {
        let key_path = self.key_descriptor.as_path();
        self.ssh_keygen.sign(key_path, namespace, message)
    }
}
