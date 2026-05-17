// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv_core::cli_api::test_support::storage::ssh::agent::traits::AgentSigner;
use secretenv_core::cli_api::test_support::storage::ssh::external::traits::SshKeygen;
use secretenv_core::cli_api::test_support::storage::ssh::protocol::types::Ed25519RawSignature;
use std::path::Path;

struct StubSshKeygen;

impl SshKeygen for StubSshKeygen {
    fn derive_public_key(&self, _key_path: &Path) -> secretenv_core::Result<String> {
        Ok(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA stub"
                .to_string(),
        )
    }

    fn sign(
        &self,
        _key_path: &Path,
        _namespace: &str,
        _ssh_pubkey: &str,
        _data: &[u8],
    ) -> secretenv_core::Result<Ed25519RawSignature> {
        Ok(Ed25519RawSignature::new([0u8; 64]))
    }

    fn verify(
        &self,
        _ssh_pubkey: &str,
        _namespace: &str,
        _message: &[u8],
        _signature: &str,
    ) -> secretenv_core::Result<()> {
        Ok(())
    }
}

pub fn stub_ssh_keygen() -> Box<dyn SshKeygen> {
    Box::new(StubSshKeygen)
}

struct StubAgentSigner;

impl AgentSigner for StubAgentSigner {
    fn sign(
        &self,
        _ssh_pubkey: &str,
        _message: &[u8],
    ) -> secretenv_core::Result<Ed25519RawSignature> {
        Ok(Ed25519RawSignature::new([0u8; 64]))
    }
}

pub fn stub_agent_signer() -> Box<dyn AgentSigner> {
    Box::new(StubAgentSigner)
}
