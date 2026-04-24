// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Crypto-specific error types

use thiserror::Error;

/// Error type for cryptographic operations.
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Invalid key format or length.
    #[error("Invalid key: {message}")]
    InvalidKey { message: String },

    /// Cryptographic operation failed (HPKE, XChaCha20-Poly1305, Ed25519, etc.).
    #[error("Operation failed: {message}")]
    OperationFailed {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Key derivation failed (HKDF, etc.).
    #[error("Key derivation failed: {message}")]
    KeyDerivationFailed { message: String },
}

impl CryptoError {
    /// Build an invalid key error.
    pub fn build_invalid_key_error(message: impl Into<String>) -> Self {
        CryptoError::InvalidKey {
            message: message.into(),
        }
    }

    /// Build an operation failed error.
    pub fn build_operation_failed_error(message: impl Into<String>) -> Self {
        CryptoError::OperationFailed {
            message: message.into(),
            source: None,
        }
    }

    /// Build an operation failed error with a source error.
    pub fn build_operation_failed_error_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        CryptoError::OperationFailed {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Build a key derivation failed error.
    pub fn build_key_derivation_error(message: impl Into<String>) -> Self {
        CryptoError::KeyDerivationFailed {
            message: message.into(),
        }
    }
}
