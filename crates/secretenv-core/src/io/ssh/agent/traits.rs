// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH agent signing trait abstraction

use crate::io::ssh::protocol::types::Ed25519RawSignature;
use crate::Result;

/// Abstraction over ssh-agent signing operations.
///
/// Implementations handle agent socket resolution and key lookup internally.
pub trait AgentSigner: Send + Sync {
    /// Sign message via ssh-agent and return Ed25519 raw signature (64 bytes).
    fn sign(&self, ssh_pubkey: &str, message: &[u8]) -> Result<Ed25519RawSignature>;
}
