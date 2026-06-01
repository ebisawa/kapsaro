// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use kapsaro_core::cli_api::test_support::storage::ssh::agent::traits::AgentSigner;
use kapsaro_core::cli_api::test_support::storage::ssh::protocol::types::Ed25519RawSignature;

struct StubAgentSigner;

impl AgentSigner for StubAgentSigner {
    fn sign(
        &self,
        _ssh_pubkey: &str,
        _message: &[u8],
    ) -> kapsaro_core::Result<Ed25519RawSignature> {
        Ok(Ed25519RawSignature::new([0u8; 64]))
    }
}

pub fn stub_agent_signer() -> Box<dyn AgentSigner> {
    Box::new(StubAgentSigner)
}
