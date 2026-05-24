// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Raw Ed25519 signature primitives.
//!
//! This module operates on raw bytes and does not handle format-specific
//! canonicalization or wire signature DTO assembly.

use crate::crypto::{build_crypto_error, build_crypto_operation_error};
use crate::format::codec::base64_public::{decode_base64url_nopad, encode_base64url_nopad};
use crate::Result;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

fn sign_bytes_raw(canonical_bytes: &[u8], signing_key: &SigningKey) -> String {
    let signature_bytes = signing_key.sign(canonical_bytes);
    encode_base64url_nopad(&signature_bytes.to_bytes())
}

/// Sign bytes and return only the base64url signature string.
pub fn sign_detached_bytes(canonical_bytes: &[u8], signing_key: &SigningKey) -> Result<String> {
    Ok(sign_bytes_raw(canonical_bytes, signing_key))
}

/// Verify a base64url Ed25519 signature over raw bytes.
pub fn verify_detached_bytes(
    canonical_bytes: &[u8],
    verifying_key: &VerifyingKey,
    signature_alg: &str,
    signature_b64: &str,
    expected_signature_alg: &str,
) -> Result<()> {
    if signature_alg != expected_signature_alg {
        return Err(build_crypto_error(
            "Unsupported signature algorithm",
            signature_alg,
        ));
    }

    let sig_bytes = decode_base64url_nopad(signature_b64, "signature")
        .map_err(|_| build_crypto_operation_error("Invalid signature Base64"))?;
    if sig_bytes.len() != 64 {
        return Err(build_crypto_error(
            "Invalid signature length",
            format!("Expected 64 bytes (Ed25519), got {}", sig_bytes.len()),
        ));
    }
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|_| build_crypto_operation_error("Invalid signature format"))?;

    verifying_key
        .verify(canonical_bytes, &sig)
        .map_err(|_| build_crypto_operation_error("Signature verification failed"))?;

    Ok(())
}
