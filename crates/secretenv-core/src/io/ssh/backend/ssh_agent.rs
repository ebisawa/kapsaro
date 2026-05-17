// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH agent backend implementation

use super::signature_backend::SignatureBackend;
use crate::io::ssh::agent::traits::AgentSigner;
use crate::io::ssh::protocol::sshsig;
use crate::io::ssh::protocol::types::Ed25519RawSignature;
use crate::Result;

/// ssh-agent backend (Method A)
///
/// Communicates directly with ssh-agent via SSH_AUTH_SOCK.
/// Requires:
/// - `SSH_AUTH_SOCK` environment variable set
/// - Target key loaded in ssh-agent
pub struct SshAgentBackend {
    agent_signer: Box<dyn AgentSigner>,
}

impl SshAgentBackend {
    pub fn new(agent_signer: Box<dyn AgentSigner>) -> Self {
        Self { agent_signer }
    }
}

impl SignatureBackend for SshAgentBackend {
    fn sign_sshsig(
        &self,
        namespace: &str,
        ssh_pubkey: &str,
        message: &[u8],
    ) -> Result<Ed25519RawSignature> {
        let sshsig_signed_data = sshsig::build_sshsig_signed_data(message, namespace);

        self.agent_signer.sign(ssh_pubkey, &sshsig_signed_data)
    }
}
