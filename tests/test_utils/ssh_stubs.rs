// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv::io::ssh::agent::traits::AgentSigner;
use secretenv::io::ssh::external::traits::SshKeygen;
use secretenv::io::ssh::protocol::types::Ed25519RawSignature;
use std::path::Path;

struct StubSshKeygen;

impl SshKeygen for StubSshKeygen {
    fn derive_public_key(&self, _key_path: &Path) -> secretenv::Result<String> {
        Ok(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA stub"
                .to_string(),
        )
    }

    fn sign(
        &self,
        _key_path: &Path,
        _namespace: &str,
        _data: &[u8],
    ) -> secretenv::Result<Ed25519RawSignature> {
        Ok(Ed25519RawSignature::new([0u8; 64]))
    }

    fn verify(
        &self,
        _ssh_pubkey: &str,
        _namespace: &str,
        _message: &[u8],
        _signature: &str,
    ) -> secretenv::Result<()> {
        Ok(())
    }
}

pub fn stub_ssh_keygen() -> Box<dyn SshKeygen> {
    Box::new(StubSshKeygen)
}

struct StubAgentSigner;

impl AgentSigner for StubAgentSigner {
    fn sign(&self, _ssh_pubkey: &str, _message: &[u8]) -> secretenv::Result<Ed25519RawSignature> {
        Ok(Ed25519RawSignature::new([0u8; 64]))
    }
}

pub fn stub_agent_signer() -> Box<dyn AgentSigner> {
    Box::new(StubAgentSigner)
}
