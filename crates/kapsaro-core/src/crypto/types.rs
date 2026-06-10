// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Type-safe cryptographic primitives
//!
//! This module provides type-safe wrappers for cryptographic data to prevent
//! confusion between different types of keys, nonces, salts, and data.

/// Macro to implement `from_slice` for fixed-size types
///
/// Usage:
/// - `impl_fixed_size_type!(TypeName, 32, "type name")` - for regular types
/// - `impl_fixed_size_type!(TypeName, 32, "type name", zeroizing)` - for Zeroizing-wrapped types
macro_rules! impl_fixed_size_type {
    ($name:ident, $size:expr, $type_name:literal) => {
        impl $name {
            /// Try to create from a slice
            ///
            /// # Errors
            ///
            /// Returns an error if the slice is not exactly $size bytes
            pub fn from_slice(bytes: &[u8]) -> $crate::Result<Self> {
                if bytes.len() != $size {
                    return Err(
                        $crate::crypto::CryptoError::build_invalid_key_error(format!(
                            "Invalid {} length: expected {} bytes, got {}",
                            $type_name,
                            $size,
                            bytes.len()
                        ))
                        .into(),
                    );
                }
                let mut out = [0u8; $size];
                out.copy_from_slice(bytes);
                Ok(Self(out))
            }
        }
    };
    ($name:ident, $size:expr, $type_name:literal, zeroizing) => {
        impl $name {
            /// Try to create from a slice
            ///
            /// # Errors
            ///
            /// Returns an error if the slice is not exactly $size bytes
            pub fn from_slice(bytes: &[u8]) -> $crate::Result<Self> {
                if bytes.len() != $size {
                    return Err(
                        $crate::crypto::CryptoError::build_invalid_key_error(format!(
                            "Invalid {} length: expected {} bytes, got {}",
                            $type_name,
                            $size,
                            bytes.len()
                        ))
                        .into(),
                    );
                }
                let mut out = ::zeroize::Zeroizing::new([0u8; $size]);
                out.as_mut().copy_from_slice(bytes);
                Ok(Self(out))
            }
        }
    };
}

pub mod data;
pub mod keys;
pub mod primitives;

#[cfg(test)]
#[path = "../../tests/unit/internal/crypto_types_test.rs"]
mod crypto_types_test;
