// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Traits for abstracting external SSH command execution.
//!
//! These traits enable dependency injection of ssh-keygen and ssh-add commands,
//! allowing mock implementations for testing without `#[cfg(test)]` conditional compilation.

use crate::io::ssh::protocol::types::Ed25519RawSignature;
use crate::Result;
use std::path::Path;

/// Abstraction over the `ssh-keygen` command.
///
/// Implementations handle temp file management internally.
pub trait SshKeygen: Send + Sync {
    /// `ssh-keygen -y -f <key_path>` — derive public key from private key.
    fn derive_public_key(&self, key_path: &Path) -> Result<String>;

    /// `ssh-keygen -Y sign` — produce an Ed25519 raw signature for IKM derivation.
    /// Implementations must avoid persisting secret signature material on disk.
    fn sign(
        &self,
        key_path: &Path,
        namespace: &str,
        ssh_pubkey: &str,
        data: &[u8],
    ) -> Result<Ed25519RawSignature>;

    /// `ssh-keygen -Y verify` — verify an SSHSIG armored signature.
    /// Temp files (allowed_signers, signature) are managed internally.
    fn verify(
        &self,
        ssh_pubkey: &str,
        namespace: &str,
        message: &[u8],
        signature: &str,
    ) -> Result<()>;
}

/// Abstraction over the `ssh-add` command.
///
/// Socket resolution (SSH_AUTH_SOCK / IdentityAgent) is handled internally.
pub trait SshAdd: Send + Sync {
    /// `ssh-add -L` — list public keys loaded in the agent.
    fn list_keys(&self) -> Result<String>;
}
