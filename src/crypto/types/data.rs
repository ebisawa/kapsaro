// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic data types with type safety

use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// Plaintext data
///
/// ```compile_fail
/// use secretenv::crypto::types::data::Plaintext;
///
/// let plaintext = Plaintext::from(b"secret" as &[u8]);
/// let _copy = plaintext.clone();
/// ```
///
/// ```compile_fail
/// use secretenv::crypto::types::data::Plaintext;
///
/// let plaintext = Plaintext::from(b"secret" as &[u8]);
/// let _bytes = plaintext.into_bytes();
/// ```
pub struct Plaintext(Vec<u8>);

impl Zeroize for Plaintext {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Plaintext {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Plaintext {
    /// Create a new plaintext from bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Get the plaintext bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to a zeroizing vector of bytes
    pub fn to_zeroizing_vec(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.clone())
    }
}

impl From<Vec<u8>> for Plaintext {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for Plaintext {
    fn from(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

impl AsRef<[u8]> for Plaintext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Plaintext")
            .field("data", &"[REDACTED]")
            .field("len", &self.0.len())
            .finish()
    }
}

/// Ciphertext data
#[derive(Debug, Clone)]
pub struct Ciphertext(Vec<u8>);

impl Ciphertext {
    /// Create a new ciphertext from bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Get the ciphertext bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert into bytes
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Convert to a vector of bytes (cloning)
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl From<Vec<u8>> for Ciphertext {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

/// Additional Authenticated Data (AAD)
#[derive(Debug, Clone)]
pub struct Aad(Vec<u8>);

impl Aad {
    /// Create a new AAD from bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Get the AAD bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create an empty AAD
    pub fn empty() -> Self {
        Self(Vec::new())
    }
}

impl From<Vec<u8>> for Aad {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for Aad {
    fn from(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

/// HKDF Info (context and application specific information)
#[derive(Debug, Clone)]
pub struct Info(Vec<u8>);

impl Info {
    /// Create a new Info from bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Get the Info bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create Info from a string
    pub fn from_string(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl From<Vec<u8>> for Info {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for Info {
    fn from(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

impl From<&str> for Info {
    fn from(s: &str) -> Self {
        Self::from_string(s)
    }
}

/// Input Keying Material (IKM) for HKDF
///
/// This is wrapped in Zeroizing for secure memory clearing.
///
/// ```compile_fail
/// use secretenv::crypto::types::data::Ikm;
///
/// let ikm = Ikm::from(b"secret" as &[u8]);
/// let _copy = ikm.clone();
/// ```
pub struct Ikm(Zeroizing<Vec<u8>>);

impl Ikm {
    /// Create a new IKM from bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self(Zeroizing::new(data))
    }

    /// Get the IKM bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Ikm {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for Ikm {
    fn from(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

/// HPKE Encapsulated Key
#[derive(Debug, Clone)]
pub struct Enc(Vec<u8>);

impl Enc {
    /// Create a new Enc from bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Get the Enc bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert into bytes
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for Enc {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}
