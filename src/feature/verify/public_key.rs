// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public key verification.

use crate::feature::context::expiry::{
    check_key_expiry, enforce_recipient_key_not_expired, KeyExpiryStatus,
};
use crate::format::jcs;
use crate::format::kid::derive_public_key_kid;
use crate::io::ssh::verify::verify_attestation;
use crate::model::public_key::{
    AttestationProof, AttestedIdentity, PublicKey, VerifiedPublicKey, VerifiedPublicKeyAttested,
    VerifiedRecipientKey,
};
use crate::model::verification::ExpiryProof;
use crate::model::verification::SelfSignatureProof;
use crate::support::codec::base64_public::{decode_base64url_nopad, decode_base64url_nopad_array};
use crate::support::kid::kid_display_lossy;
use crate::{Error, Result};
use ed25519_dalek::{Verifier, VerifyingKey};
use time::OffsetDateTime;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct VerifiedPublicKeyForVerification {
    pub verified_public_key: VerifiedPublicKeyAttested,
    pub warnings: Vec<String>,
}

/// Verify PublicKey document self-signature only and return VerifiedPublicKey
///
/// # Arguments
/// * `public_key` - PublicKey document to verify
/// * `debug` - Enable debug logging
///
/// # Returns
/// `VerifiedPublicKey` if self-signature is valid, error otherwise
pub fn verify_public_key(public_key: &PublicKey, debug: bool) -> Result<VerifiedPublicKey> {
    validate_derived_kid(public_key)?;

    let protected_jcs = jcs::normalize(&public_key.protected)
        .map_err(|e| Error::crypto_with_source("Failed to normalize PublicKey protected", e))?;
    let verifying_key_bytes: [u8; 32] = decode_base64url_nopad_array(
        &public_key.protected.identity.keys.sig.x,
        "Ed25519 public key",
    )?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|e| Error::crypto_with_source("Invalid Ed25519 public key", e))?;

    let sig_bytes = decode_base64url_nopad(&public_key.signature, "signature")
        .map_err(|e| Error::crypto_with_source("Failed to decode PublicKey signature", e))?;
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| Error::crypto_with_source("Invalid signature format", e))?;

    verifying_key.verify(&protected_jcs, &sig).map_err(|e| {
        Error::crypto_with_source("PublicKey self-signature verification failed", e)
    })?;

    if debug {
        debug!("[VERIFY] PublicKey self-signature verified");
    }

    let proof = SelfSignatureProof::new();
    Ok(VerifiedPublicKey::new(public_key.clone(), proof))
}

/// Verify PublicKey document (self-signature and attestation) and return VerifiedPublicKeyAttested
///
/// # Arguments
/// * `public_key` - PublicKey document to verify
/// * `debug` - Enable debug logging
///
/// # Returns
/// `VerifiedPublicKeyAttested` if verification succeeds, error otherwise
pub fn verify_public_key_with_attestation(
    public_key: &PublicKey,
    debug: bool,
) -> Result<VerifiedPublicKeyAttested> {
    let verified = verify_public_key(public_key, debug)?;

    // Verify attestation
    verify_attestation(
        &public_key.protected.identity.keys,
        &public_key.protected.identity.attestation.pub_,
        &public_key.protected.identity.attestation.sig,
    )?;

    if debug {
        debug!("[VERIFY] PublicKey attestation verified");
    }

    let proof = AttestationProof {
        method: public_key.protected.identity.attestation.method.clone(),
        ssh_pub: public_key.protected.identity.attestation.pub_.clone(),
        verified_at: None,
    };
    let attested_identity = AttestedIdentity::new(public_key.protected.identity.clone(), proof);

    Ok(VerifiedPublicKeyAttested::new(
        public_key.clone(),
        verified.self_signature_proof().clone(),
        attested_identity,
    ))
}

pub fn verify_public_key_for_verification(
    public_key: &PublicKey,
    debug: bool,
) -> Result<VerifiedPublicKeyForVerification> {
    let verified_public_key = verify_public_key_with_attestation(public_key, debug)?;
    let mut warnings = Vec::new();
    if let Some(warning) = public_key_expiry_warning(verified_public_key.document())? {
        warnings.push(warning);
    }
    Ok(VerifiedPublicKeyForVerification {
        verified_public_key,
        warnings,
    })
}

/// Verify multiple recipient public keys for wrap (encryption) operations.
///
/// Enforces that none of the recipient keys are expired.
/// Returns `VerifiedRecipientKey` which is the only type accepted by wrap functions,
/// providing a compile-time guarantee that expiry has been checked.
pub fn verify_recipient_public_keys(
    keys: &[PublicKey],
    debug: bool,
) -> Result<Vec<VerifiedRecipientKey>> {
    keys.iter()
        .map(|key| {
            enforce_recipient_key_not_expired(key)?;
            let attested = verify_public_key_with_attestation(key, debug)?;
            Ok(VerifiedRecipientKey::new(attested, ExpiryProof::new()))
        })
        .collect()
}

fn validate_derived_kid(public_key: &PublicKey) -> Result<()> {
    let mut protected_without_kid = serde_json::to_value(&public_key.protected)?;
    let object = protected_without_kid.as_object_mut().ok_or_else(|| {
        Error::verify("V-KID-DERIVED", "PublicKey protected must be a JSON object")
    })?;
    object.remove("kid");

    let derived_kid = derive_public_key_kid(&protected_without_kid)?;
    if public_key.protected.kid != derived_kid {
        return Err(Error::verify(
            "V-KID-DERIVED",
            format!(
                "PublicKey protected.kid '{}' does not match derived kid '{}'",
                kid_display_lossy(&public_key.protected.kid),
                kid_display_lossy(&derived_kid)
            ),
        ));
    }

    Ok(())
}

pub(crate) fn public_key_expiry_warning(doc: &PublicKey) -> Result<Option<String>> {
    if doc.protected.expires_at.is_empty() {
        return Ok(None);
    }
    match check_key_expiry(&doc.protected.expires_at, OffsetDateTime::now_utc())? {
        KeyExpiryStatus::Valid => Ok(None),
        KeyExpiryStatus::ExpiringSoon {
            expires_at,
            days_remaining,
        } => Ok(Some(format!(
            "PublicKey for '{}' expires in {} days (expires_at: {})",
            doc.protected.member_id, days_remaining, expires_at
        ))),
        KeyExpiryStatus::Expired { expires_at } => Ok(Some(format!(
            "PublicKey for '{}' has expired (expires_at: {})",
            doc.protected.member_id, expires_at
        ))),
    }
}
