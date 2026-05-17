// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic primitives for secretenv v3
//!
//! Implements HPKE (RFC9180), XChaCha20-Poly1305, Ed25519, and HKDF-SHA256

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

/// Creates a cryptographic error with a formatted message and source error
///
/// # Arguments
/// * `operation` - The operation that failed (e.g., "XChaCha20-Poly1305 encryption")
/// * `details` - Additional error details
/// * `source` - The underlying error that caused this failure
pub fn build_crypto_error_with_source(
    operation: &str,
    details: impl std::fmt::Display,
    source: impl std::error::Error + Send + Sync + 'static,
) -> crate::Error {
    CryptoError::build_operation_failed_error_with_source(
        format!("{}: {}", operation, details),
        source,
    )
    .into()
}

pub(crate) mod aead;
pub(crate) mod kdf;
pub(crate) mod kem;
pub(crate) mod rng;
pub(crate) mod sign;
pub(crate) mod types;
