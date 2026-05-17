// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH signing facade types.

use crate::io::ssh::backend::SignatureBackend as InternalSignatureBackend;
use crate::io::ssh::protocol::types::Ed25519RawSignature;
use crate::Result;

/// SSHSIG-compatible Ed25519 raw signature returned by caller-supplied backends.
#[derive(Clone, PartialEq, Eq)]
pub struct SshRawSignature {
    inner: Ed25519RawSignature,
}

/// Caller-supplied SSH signing backend for facade APIs.
pub trait SshSignatureBackend {
    /// Sign message bytes in a specific SSHSIG namespace.
    fn sign_sshsig(
        &self,
        namespace: &str,
        ssh_pubkey: &str,
        message: &[u8],
    ) -> Result<SshRawSignature>;
}

impl SshRawSignature {
    /// Build a raw signature from exactly 64 bytes.
    pub fn new(bytes: [u8; 64]) -> Self {
        Self {
            inner: Ed25519RawSignature::new(bytes),
        }
    }

    /// Return the raw signature bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        self.inner.as_bytes()
    }

    pub(crate) fn into_internal(self) -> Ed25519RawSignature {
        self.inner
    }
}

impl std::fmt::Debug for SshRawSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SshRawSignature([REDACTED])")
    }
}

pub(crate) fn into_internal_backend(
    backend: Box<dyn SshSignatureBackend>,
) -> Box<dyn InternalSignatureBackend> {
    Box::new(SshSignatureBackendAdapter { backend })
}

struct SshSignatureBackendAdapter {
    backend: Box<dyn SshSignatureBackend>,
}

impl InternalSignatureBackend for SshSignatureBackendAdapter {
    fn sign_sshsig(
        &self,
        namespace: &str,
        ssh_pubkey: &str,
        message: &[u8],
    ) -> Result<Ed25519RawSignature> {
        self.backend
            .sign_sshsig(namespace, ssh_pubkey, message)
            .map(SshRawSignature::into_internal)
    }
}
