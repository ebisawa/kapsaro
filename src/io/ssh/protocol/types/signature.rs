// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::io::ssh::SshError;
use crate::Result;
use zeroize::Zeroizing;

/// Ed25519 raw signature (64 bytes)
///
/// This is the canonical form used as IKM (Input Keying Material) for key derivation.
/// It represents the raw Ed25519 signature bytes as specified in RFC 8709.
///
/// This is wrapped in Zeroizing for secure memory clearing, as it is used as
/// input keying material for key derivation and contains sensitive cryptographic data.
#[derive(Clone)]
pub struct Ed25519RawSignature(Zeroizing<[u8; 64]>);

impl PartialEq for Ed25519RawSignature {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.as_ref().ct_eq(other.0.as_ref()).into()
    }
}

impl Eq for Ed25519RawSignature {}

impl std::fmt::Debug for Ed25519RawSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ed25519RawSignature([REDACTED])")
    }
}

impl Ed25519RawSignature {
    /// Create a new Ed25519RawSignature from 64 bytes
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(super) fn from_zeroizing(bytes: Zeroizing<[u8; 64]>) -> Self {
        Self(bytes)
    }

    /// Get the raw signature bytes
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Convert to a vector of bytes
    pub fn to_vec(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_vec())
    }

    /// Try to create from a slice
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(SshError::operation_failed(format!(
                "Invalid Ed25519 signature length: expected 64 bytes, got {}",
                bytes.len()
            ))
            .into());
        }
        let mut out = Zeroizing::new([0u8; 64]);
        out.as_mut().copy_from_slice(bytes);
        Ok(Self::from_zeroizing(out))
    }
}
