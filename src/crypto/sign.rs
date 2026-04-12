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
use crate::model::signature::ArtifactSignature;
use crate::model::trust_store::TrustStoreSignature;
use crate::support::codec::base64_public::{decode_base64url_nopad, encode_base64url_nopad};
use crate::Result;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

fn sign_bytes_raw(
    canonical_bytes: &[u8],
    signing_key: &SigningKey,
    signature_alg: &str,
) -> (String, String) {
    let signature_bytes = signing_key.sign(canonical_bytes);
    let sig_b64 = encode_base64url_nopad(&signature_bytes.to_bytes());
    (signature_alg.to_string(), sig_b64)
}

/// Sign bytes and return only the base64url signature string.
///
/// Used for self-signatures (e.g., PublicKey documents) where only the
/// raw signature is needed, not a full signature structure.
pub fn sign_detached_bytes(
    canonical_bytes: &[u8],
    signing_key: &SigningKey,
    signature_alg: &str,
) -> Result<String> {
    let (_alg, sig) = sign_bytes_raw(canonical_bytes, signing_key, signature_alg);
    Ok(sig)
}

/// Build an artifact signature that embeds `signer_pub`.
pub fn sign_artifact_bytes(
    canonical_bytes: &[u8],
    signing_key: &SigningKey,
    signer_kid: &str,
    signer_pub: PublicKey,
    signature_alg: &str,
) -> Result<ArtifactSignature> {
    let (alg, sig) = sign_bytes_raw(canonical_bytes, signing_key, signature_alg);

    Ok(ArtifactSignature {
        alg,
        kid: signer_kid.to_string(),
        signer_pub,
        sig,
    })
}

/// Build a trust store signature without embedding `signer_pub`.
pub fn sign_trust_store_bytes(
    canonical_bytes: &[u8],
    signing_key: &SigningKey,
    signer_kid: &str,
    signature_alg: &str,
) -> Result<TrustStoreSignature> {
    let (alg, sig) = sign_bytes_raw(canonical_bytes, signing_key, signature_alg);

    Ok(TrustStoreSignature {
        alg,
        kid: signer_kid.to_string(),
        sig,
    })
}

fn verify_signature_components(
    canonical_bytes: &[u8],
    verifying_key: &VerifyingKey,
    signature_alg: &str,
    signature_b64: &str,
    expected_signature_alg: &str,
) -> Result<()> {
    if signature_alg != expected_signature_alg {
        return Err(crypto_error(
            "Unsupported signature algorithm",
            signature_alg,
        ));
    }

    let sig_bytes = decode_base64url_nopad(signature_b64, "signature")
        .map_err(|_| crypto_operation_failed("Invalid signature Base64"))?;
    if sig_bytes.len() != 64 {
        return Err(crypto_error(
            "Invalid signature length",
            format!("Expected 64 bytes (Ed25519), got {}", sig_bytes.len()),
        ));
    }
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|_| crypto_operation_failed("Invalid signature format"))?;

    verifying_key
        .verify(canonical_bytes, &sig)
        .map_err(|_| crypto_operation_failed("Signature verification failed"))?;

    Ok(())
}

/// Verify an artifact signature using Ed25519 (RFC 8032 PureEdDSA).
pub fn verify_artifact_bytes(
    canonical_bytes: &[u8],
    verifying_key: &VerifyingKey,
    signature: &ArtifactSignature,
    expected_signature_alg: &str,
) -> Result<()> {
    verify_signature_components(
        canonical_bytes,
        verifying_key,
        &signature.alg,
        &signature.sig,
        expected_signature_alg,
    )
}

/// Verify a trust store signature using Ed25519 (RFC 8032 PureEdDSA).
pub fn verify_trust_store_bytes(
    canonical_bytes: &[u8],
    verifying_key: &VerifyingKey,
    signature: &TrustStoreSignature,
    expected_signature_alg: &str,
) -> Result<()> {
    verify_signature_components(
        canonical_bytes,
        verifying_key,
        &signature.alg,
        &signature.sig,
        expected_signature_alg,
    )
}
