// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Fixed-size cryptographic primitive types with type safety

use crate::crypto::rng::generate_random_array;
use crate::Result;

/// XChaCha20-Poly1305 nonce (24 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XChaChaNonce([u8; 24]);

impl XChaChaNonce {
    /// Create a new XChaCha nonce from 24 bytes
    pub fn new(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }

    /// Get the nonce bytes
    pub fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }
}

/// Fresh XChaCha20-Poly1305 nonce generated for a single encryption.
///
/// Built only by `generate`, so a nonce reaching an encryption call came from
/// the CSPRNG rather than from bytes a caller chose.
#[derive(Debug)]
pub struct FreshXChaChaNonce(XChaChaNonce);

impl FreshXChaChaNonce {
    /// Generate a fresh nonce from the OS CSPRNG.
    pub(crate) fn generate() -> Result<Self> {
        Ok(Self(XChaChaNonce(generate_random_array::<24>()?)))
    }

    /// Get the nonce bytes.
    pub fn as_bytes(&self) -> &[u8; 24] {
        self.0.as_bytes()
    }

    /// Convert to a stored nonce after encryption.
    pub(crate) fn into_stored(self) -> XChaChaNonce {
        self.0
    }
}

/// Trait for types that can be used as HKDF salt in key derivation.
///
/// Only types intended for HKDF-Extract should implement this trait.
/// This prevents accidental misuse of other salt types (e.g., IKM salts)
/// in HKDF operations.
pub trait AsHkdfSalt {
    /// Return the salt bytes for HKDF-Extract.
    fn as_hkdf_salt_bytes(&self) -> &[u8];
}

/// PrivateKey IKM salt (32 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKeyIkmSalt([u8; 32]);

impl PrivateKeyIkmSalt {
    /// Create a new PrivateKey IKM salt from 32 bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the IKM salt bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// HKDF salt (32 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HkdfSalt([u8; 32]);

impl HkdfSalt {
    /// Create a new HKDF salt from 32 bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the HKDF salt bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsHkdfSalt for HkdfSalt {
    fn as_hkdf_salt_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Artifact key schedule salt: the domain-separating context bytes an artifact
/// binds its key schedule to. Variable length, unlike the fixed 32-byte
/// [`HkdfSalt`] a protected private key is derived with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactKeyScheduleSalt(Vec<u8>);

impl ArtifactKeyScheduleSalt {
    /// Create an artifact key schedule salt from its context bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsHkdfSalt for ArtifactKeyScheduleSalt {
    fn as_hkdf_salt_bytes(&self) -> &[u8] {
        &self.0
    }
}
