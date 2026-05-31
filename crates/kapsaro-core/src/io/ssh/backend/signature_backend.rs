// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Signature backend trait

use crate::io::ssh::protocol::types::Ed25519RawSignature;
use crate::io::ssh::SshError;
use crate::Result;

/// Signature backend producing SSHSIG-compatible signature blobs
///
/// This trait abstracts the signature acquisition mechanism.
/// Both implementations (ssh-agent and ssh-keygen) produce equivalent output:
/// Ed25519 raw signature bytes (64 bytes, RFC 8709), derived from the SSH
/// signature blob (SSH wire `string algorithm` + `string signature`).
pub trait SignatureBackend {
    /// Sign message bytes in a specific SSHSIG namespace.
    ///
    /// # Arguments
    ///
    /// * `namespace` - SSHSIG namespace for the signature context
    /// * `ssh_pubkey` - SSH public key in authorized_keys format
    /// * `message` - Raw message to wrap in SSHSIG signed_data and sign
    ///
    /// # Returns
    ///
    /// Ed25519 raw signature (64 bytes) extracted from the SSHSIG output.
    ///
    /// # Errors
    ///
    /// Returns detailed diagnostic errors if signing fails
    fn sign_sshsig(
        &self,
        namespace: &str,
        ssh_pubkey: &str,
        message: &[u8],
    ) -> Result<Ed25519RawSignature>;

    /// Sign message bytes and ensure the derived signature is deterministic.
    ///
    /// This signs the same challenge twice and returns the first signature only
    /// when both results match byte-for-byte.
    fn sign_sshsig_deterministic(
        &self,
        namespace: &str,
        ssh_pubkey: &str,
        message: &[u8],
    ) -> Result<Ed25519RawSignature> {
        let sig1 = self.sign_sshsig(namespace, ssh_pubkey, message)?;
        let sig2 = self.sign_sshsig(namespace, ssh_pubkey, message)?;

        if sig1 != sig2 {
            return Err(SshError::build_operation_failed_error(
                "Non-deterministic signature detected: same input produced different signatures",
            )
            .into());
        }

        Ok(sig1)
    }

    /// Check that signing is deterministic
    ///
    /// Signs the same challenge twice and verifies identical output.
    /// This is critical for SA-SIG-KDF correctness.
    ///
    /// # Errors
    ///
    /// Returns error if signatures differ or signing fails
    fn check_sshsig_determinism(
        &self,
        namespace: &str,
        ssh_pubkey: &str,
        message: &[u8],
    ) -> Result<()> {
        let _ = self.sign_sshsig_deterministic(namespace, ssh_pubkey, message)?;
        Ok(())
    }
}
