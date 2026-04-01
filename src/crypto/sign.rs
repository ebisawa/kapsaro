// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Digital signature algorithms
//!
//! Low-level cryptographic primitives for digital signatures.
//! Format-specific canonicalization (e.g., JCS normalization) is handled
//! in higher layers (e.g., `core/services/signature`).
//!
//! Ed25519 signature primitives
//!
//! Low-level cryptographic operations for Ed25519 signatures.
//! This module operates on raw bytes and does not handle format-specific
//! canonicalization (e.g., JCS normalization). Format-specific signing
//! should be implemented in higher layers (e.g., `core/services/signature`).

use crate::crypto::{crypto_error, crypto_operation_failed};
use crate::model::public_key::PublicKey;
use crate::model::signature::Signature;
use crate::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

/// Signs bytes using Ed25519 (RFC 8032 PureEdDSA).
///
/// This is a low-level primitive that signs the canonical bytes directly
/// according to RFC 8032 PureEdDSA specification. No pre-hashing is performed.
/// Format-specific canonicalization (e.g., JCS normalization) must be done
/// by the caller before calling this function.
///
/// # Arguments
/// * `canonical_bytes` - Pre-canonicalized bytes to sign
/// * `signing_key` - Ed25519 signing key
/// * `signer_kid` - Key ID of the public key statement used for signing
/// * `signer_pub` - Optional PublicKey document to embed in signature
/// * `signature_alg` - On-wire `signature.alg` value (caller supplies; v3 uses `crate::model::identifiers::alg::SIGNATURE_ED25519`)
///
/// # Returns
/// Signature structure (alg, kid, signer_pub, sig)
pub fn sign_bytes(
    canonical_bytes: &[u8],
    signing_key: &SigningKey,
    signer_kid: &str,
    signer_pub: Option<PublicKey>,
    signature_alg: &str,
) -> Result<Signature> {
    // Sign canonical_bytes directly (RFC 8032 PureEdDSA)
    let signature_bytes = signing_key.sign(canonical_bytes);
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature_bytes.to_bytes());

    Ok(Signature {
        alg: signature_alg.to_string(),
        kid: signer_kid.to_string(),
        signer_pub,
        sig: sig_b64,
    })
}

/// Verifies bytes signature using Ed25519 (RFC 8032 PureEdDSA).
///
/// This is a low-level primitive that verifies the signature against the
/// canonical bytes directly according to RFC 8032 PureEdDSA specification.
/// No pre-hashing is performed. Format-specific canonicalization must
/// be done by the caller before calling this function.
///
/// # Arguments
/// * `canonical_bytes` - Pre-canonicalized bytes to verify
/// * `verifying_key` - Ed25519 verifying key
/// * `signature` - Signature to verify
/// * `expected_signature_alg` - Allowed on-wire `signature.alg` (must match `signature.alg` for verification to proceed)
pub fn verify_bytes(
    canonical_bytes: &[u8],
    verifying_key: &VerifyingKey,
    signature: &Signature,
    expected_signature_alg: &str,
) -> Result<()> {
    // Step 1: Verify algorithm
    if signature.alg != expected_signature_alg {
        return Err(crypto_error(
            "Unsupported signature algorithm",
            &signature.alg,
        ));
    }

    // Step 2: Decode signature and validate length (must be 64 bytes for Ed25519)
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&signature.sig)
        .map_err(|_| crypto_operation_failed("Invalid signature Base64"))?;
    if sig_bytes.len() != 64 {
        return Err(crypto_error(
            "Invalid signature length",
            format!("Expected 64 bytes (Ed25519), got {}", sig_bytes.len()),
        ));
    }
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|_| crypto_operation_failed("Invalid signature format"))?;

    // Step 3: Verify signature against canonical_bytes directly (RFC 8032 PureEdDSA)
    verifying_key
        .verify(canonical_bytes, &sig)
        .map_err(|_| crypto_operation_failed("Signature verification failed"))?;

    Ok(())
}
