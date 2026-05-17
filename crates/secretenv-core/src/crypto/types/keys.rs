// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic key types with type safety

use zeroize::Zeroizing;

/// XChaCha20-Poly1305 encryption key (32 bytes)
///
/// This key is wrapped in Zeroizing for secure memory clearing.
pub struct XChaChaKey(Zeroizing<[u8; 32]>);

impl XChaChaKey {
    /// Create a new XChaCha key from 32 bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Create a new XChaCha key from zeroizing bytes without an extra copy.
    pub fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl_fixed_size_type!(XChaChaKey, 32, "XChaCha key", zeroizing);

/// Master key for file-level encryption (32 bytes)
///
/// This key is wrapped in Zeroizing for secure memory clearing.
pub struct MasterKey(Zeroizing<[u8; 32]>);

impl MasterKey {
    /// Create a new master key from 32 bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Create a new master key from zeroizing bytes without an extra copy.
    pub fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl_fixed_size_type!(MasterKey, 32, "master key", zeroizing);

/// Content Encryption Key (32 bytes)
///
/// This key is wrapped in Zeroizing for secure memory clearing.
pub struct Cek(Zeroizing<[u8; 32]>);

impl Cek {
    /// Create a new CEK from 32 bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Create a new CEK from zeroizing bytes without an extra copy.
    pub fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl_fixed_size_type!(Cek, 32, "CEK", zeroizing);
