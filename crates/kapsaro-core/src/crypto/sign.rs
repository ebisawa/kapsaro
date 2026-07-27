// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Raw Ed25519 signature primitives.
//!
//! This module operates on raw bytes and does not handle format-specific
//! canonicalization or wire signature DTO assembly.

use crate::crypto::{build_crypto_error, build_crypto_operation_error};
use crate::Result;
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, VerifyingKey};

pub type Ed25519SignatureBytes = [u8; 64];

/// Sign bytes and return the raw Ed25519 signature bytes.
pub fn sign_detached_bytes(
    message_bytes: &[u8],
    signing_key: &SigningKey,
) -> Result<Ed25519SignatureBytes> {
    Ok(signing_key.sign(message_bytes).to_bytes())
}

/// Verify a parsed Ed25519 signature over raw bytes.
///
/// This is the only verification entry point in the crate. It uses
/// `verify_strict`, which rejects a small-order verifying key and a
/// small-order signature `R` point. Without those checks a single signature
/// verifies under arbitrary messages, so accepting a signature would no longer
/// imply that some private key holder produced it.
pub fn verify_detached_signature(
    message_bytes: &[u8],
    verifying_key: &VerifyingKey,
    signature: &Signature,
) -> std::result::Result<(), SignatureError> {
    verifying_key.verify_strict(message_bytes, signature)
}

/// Verify a raw Ed25519 signature over raw bytes.
pub fn verify_detached_bytes(
    message_bytes: &[u8],
    verifying_key: &VerifyingKey,
    signature_bytes: &[u8],
) -> Result<()> {
    if signature_bytes.len() != 64 {
        return Err(build_crypto_error(
            "Invalid signature length",
            format!("Expected 64 bytes (Ed25519), got {}", signature_bytes.len()),
        ));
    }
    let sig = Signature::from_slice(signature_bytes)
        .map_err(|_| build_crypto_operation_error("Invalid signature format"))?;

    verify_detached_signature(message_bytes, verifying_key, &sig)
        .map_err(|_| build_crypto_operation_error("Signature verification failed"))?;

    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/internal/crypto_sign_ed25519_test.rs"]
mod crypto_sign_ed25519_test;
