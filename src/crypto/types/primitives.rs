// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Fixed-size cryptographic primitive types with type safety

/// XChaCha20-Poly1305 nonce (24 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XChaChaNonce([u8; 24]);

impl XChaChaNonce {
    /// Size of XChaCha nonce in bytes
    pub const SIZE: usize = 24;

    /// Create a new XChaCha nonce from 24 bytes
    pub fn new(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }

    /// Get the nonce bytes
    pub fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }
}

impl_fixed_size_type!(XChaChaNonce, 24, "XChaCha nonce");

/// Trait for types that can be used as HKDF salt in key derivation.
///
/// Only types intended for HKDF-Extract should implement this trait.
/// This prevents accidental misuse of other salt types (e.g., IKM salts)
/// in HKDF operations.
pub trait AsHkdfSalt {
    /// Return the salt bytes for HKDF-Extract.
    fn as_hkdf_salt_bytes(&self) -> &[u8];
}

/// kv-enc HKDF salt (32 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvSalt([u8; 32]);

impl KvSalt {
    /// Create a new kv salt from 32 bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the kv salt bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl_fixed_size_type!(KvSalt, 32, "kv salt");

impl AsHkdfSalt for KvSalt {
    fn as_hkdf_salt_bytes(&self) -> &[u8] {
        &self.0
    }
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

impl_fixed_size_type!(PrivateKeyIkmSalt, 32, "private key ikm salt");

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

impl_fixed_size_type!(HkdfSalt, 32, "HKDF salt");

impl AsHkdfSalt for HkdfSalt {
    fn as_hkdf_salt_bytes(&self) -> &[u8] {
        &self.0
    }
}
