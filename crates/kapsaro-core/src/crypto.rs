// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic primitives for kapsaro v3
//!
//! Implements HPKE (RFC9180), XChaCha20-Poly1305, Ed25519, HKDF-SHA256, and HMAC-SHA256

pub(crate) mod error;

pub use error::CryptoError;

/// Creates a cryptographic operation error without exposing inner details
pub fn build_crypto_operation_error(message: impl Into<String>) -> crate::Error {
    CryptoError::build_operation_failed_error(message).into()
}

/// Creates a cryptographic error with a formatted message
///
/// # Arguments
/// * `operation` - The operation that failed (e.g., "XChaCha20-Poly1305 encryption")
/// * `details` - Additional error details
pub fn build_crypto_error(operation: &str, details: impl std::fmt::Display) -> crate::Error {
    CryptoError::build_operation_failed_error(format!("{}: {}", operation, details)).into()
}

pub(crate) mod aead;
pub(crate) mod hmac;
pub(crate) mod kdf;
pub(crate) mod kem;
pub(crate) mod rng;
pub(crate) mod sign;
pub(crate) mod types;

#[cfg(test)]
#[path = "../tests/unit/internal/crypto_hmac_internal_test.rs"]
mod crypto_hmac_internal_test;

#[cfg(test)]
#[path = "../tests/unit/internal/crypto_test.rs"]
mod crypto_test;
