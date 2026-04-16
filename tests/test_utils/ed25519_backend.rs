// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Ed25519 direct signing backend for tests
//!
//! Replaces SshKeygenBackend in tests to avoid spawning ssh-keygen subprocesses.
//! Signs SSHSIG signed_data directly with ed25519_dalek, producing identical
//! Ed25519RawSignature output.

use ed25519_dalek::{Signer, SigningKey};
use secretenv::io::ssh::backend::SignatureBackend;
use secretenv::io::ssh::protocol::sshsig;
use secretenv::io::ssh::protocol::types::Ed25519RawSignature;
use secretenv::Result;
use std::path::Path;

/// Test-only SignatureBackend that signs directly with Ed25519
///
/// Parses an OpenSSH Ed25519 private key file and signs SSHSIG signed_data
/// in-process, eliminating the need for ssh-keygen subprocess calls.
pub struct Ed25519DirectBackend {
    signing_key: SigningKey,
}

impl Ed25519DirectBackend {
    /// Load Ed25519 private key from OpenSSH format file
    pub fn new(ssh_key_path: &Path) -> Result<Self> {
        let private_key = ssh_key::PrivateKey::read_openssh_file(ssh_key_path).map_err(|e| {
            secretenv::Error::Ssh {
                message: format!("Failed to read SSH key: {}", e),
                source: Some(Box::new(e)),
            }
        })?;

        let key_data = private_key.key_data();
        let ed25519_keypair = key_data.ed25519().ok_or_else(|| secretenv::Error::Ssh {
            message: "SSH key is not Ed25519".to_string(),
            source: None,
        })?;

        let secret_bytes: [u8; 32] = ed25519_keypair.private.to_bytes();

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        Ok(Self { signing_key })
    }
}

impl SignatureBackend for Ed25519DirectBackend {
    fn sign_sshsig(
        &self,
        namespace: &str,
        _ssh_pubkey: &str,
        message: &[u8],
    ) -> Result<Ed25519RawSignature> {
        let sshsig_signed_data = sshsig::build_sshsig_signed_data(message, namespace);
        let signature = self.signing_key.sign(&sshsig_signed_data);
        Ok(Ed25519RawSignature::new(signature.to_bytes()))
    }
}
