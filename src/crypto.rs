// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic primitives for secretenv v3
//!
//! Implements HPKE (RFC9180), XChaCha20-Poly1305, Ed25519, and HKDF-SHA256

pub mod error;

pub use error::CryptoError;

/// Creates a cryptographic operation error without exposing inner details
pub fn crypto_operation_failed(message: impl Into<String>) -> crate::Error {
    CryptoError::operation_failed(message).into()
}

/// Creates a cryptographic error with a formatted message
///
/// # Arguments
/// * `operation` - The operation that failed (e.g., "XChaCha20-Poly1305 encryption")
/// * `details` - Additional error details
pub fn crypto_error(operation: &str, details: impl std::fmt::Display) -> crate::Error {
    CryptoError::operation_failed(format!("{}: {}", operation, details)).into()
}

/// Creates a cryptographic error with a formatted message and source error
///
/// # Arguments
/// * `operation` - The operation that failed (e.g., "XChaCha20-Poly1305 encryption")
/// * `details` - Additional error details
/// * `source` - The underlying error that caused this failure
pub fn crypto_error_with_source(
    operation: &str,
    details: impl std::fmt::Display,
    source: impl std::error::Error + Send + Sync + 'static,
) -> crate::Error {
    CryptoError::operation_failed_with_source(format!("{}: {}", operation, details), source).into()
}

pub mod aead;
pub mod kdf;
pub mod kem;
pub(crate) mod rng;
pub mod sign;
pub mod types;
