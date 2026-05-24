// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public key verification.

use crate::feature::context::expiry::{
    check_key_expiry, enforce_recipient_key_not_expired, KeyExpiryStatus,
};
use crate::format::codec::base64_public::{decode_base64url_nopad, decode_base64url_nopad_array};
use crate::format::jcs;
use crate::format::kid::derive_public_key_kid;
use crate::io::ssh::verify::verify_attestation;
use crate::model::public_key::{
    AttestationProof, AttestedIdentity, PublicKey, VerifiedPublicKeyAttested, VerifiedRecipientKey,
    VerifiedSigningPublicKey,
};
use crate::model::verification::ExpiryProof;
use crate::model::verification::SelfSignatureProof;
use crate::support::display::sanitize_display_field;
use crate::support::kid::{format_kid_display_lossy, format_kid_half_display_lossy};
use crate::{Error, Result};
use ed25519_dalek::{Verifier, VerifyingKey};
use time::OffsetDateTime;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct VerifiedPublicKeyForVerification {
    pub verified_public_key: VerifiedSigningPublicKey,
    pub warnings: Vec<String>,
}

struct PublicKeySelfSignatureVerification {
    proof: SelfSignatureProof,
    verifying_key: VerifyingKey,
}

const DEFAULT_PUBLIC_KEY_VERIFY_CONTEXT: &str = "public key";
pub(crate) const KEYSTORE_SIBLING_PUBLIC_KEY_CONTEXT: &str = "keystore sibling public.json";
pub(crate) const EMBEDDED_SIGNER_PUB_CONTEXT: &str = "embedded signer_pub";
pub(crate) const WORKSPACE_ACTIVE_MEMBER_RECIPIENT_CONTEXT: &str =
    "workspace active member recipient validation";
pub(crate) const WORKSPACE_ACTIVE_MEMBER_READ_TRUST_CONTEXT: &str = "active member/read trust";
pub(crate) const WORKSPACE_INCOMING_MEMBER_CONTEXT: &str = "workspace incoming member";
pub(crate) const WORKSPACE_MEMBER_FILE_CONTEXT: &str = "workspace member file";
pub(crate) const MEMBER_VERIFICATION_INPUT_CONTEXT: &str = "member verification input public key";
pub(crate) const TRUST_STORE_KEYSTORE_PUBLIC_KEY_CONTEXT: &str = "trust store keystore public key";

fn verify_public_key_self_signature_context(
    public_key: &PublicKey,
    debug: bool,
    context: &str,
) -> Result<PublicKeySelfSignatureVerification> {
    validate_derived_kid(public_key)?;
    log_public_key_verification(debug, public_key, context, "self-signature");

    let protected_jcs = jcs::normalize(&public_key.protected).map_err(|e| {
        Error::build_crypto_error_with_source("Failed to normalize PublicKey protected", e)
    })?;
    let verifying_key_bytes: [u8; 32] = decode_base64url_nopad_array(
        &public_key.protected.identity.keys.sig.x,
        "Ed25519 public key",
    )?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|e| Error::build_crypto_error_with_source("Invalid Ed25519 public key", e))?;

    let sig_bytes = decode_base64url_nopad(&public_key.signature, "signature").map_err(|e| {
        Error::build_crypto_error_with_source("Failed to decode PublicKey signature", e)
    })?;
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| Error::build_crypto_error_with_source("Invalid signature format", e))?;

    verifying_key.verify(&protected_jcs, &sig).map_err(|e| {
        Error::build_crypto_error_with_source("PublicKey self-signature verification failed", e)
    })?;

    Ok(PublicKeySelfSignatureVerification {
        proof: SelfSignatureProof::new(),
        verifying_key,
    })
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
    verify_public_key_with_attestation_context(public_key, debug, DEFAULT_PUBLIC_KEY_VERIFY_CONTEXT)
}

pub fn verify_public_key_with_attestation_context(
    public_key: &PublicKey,
    debug: bool,
    context: &str,
) -> Result<VerifiedPublicKeyAttested> {
    Ok(
        verify_signing_public_key_context(public_key, debug, context)?
            .attested()
            .clone(),
    )
}

fn verify_signing_public_key_context(
    public_key: &PublicKey,
    debug: bool,
    context: &str,
) -> Result<VerifiedSigningPublicKey> {
    let verified = verify_public_key_self_signature_context(public_key, debug, context)?;

    // Verify attestation
    log_public_key_verification(debug, public_key, context, "attestation");
    verify_attestation(
        &public_key.protected.identity.keys,
        &public_key.protected.identity.attestation.pub_,
        &public_key.protected.identity.attestation.sig,
    )?;

    let proof = AttestationProof {
        method: public_key.protected.identity.attestation.method.clone(),
        ssh_pub: public_key.protected.identity.attestation.pub_.clone(),
        verified_at: None,
    };
    let attested_identity = AttestedIdentity::new(public_key.protected.identity.clone(), proof);

    let attested =
        VerifiedPublicKeyAttested::new(public_key.clone(), verified.proof, attested_identity);

    Ok(VerifiedSigningPublicKey::new(
        attested,
        verified.verifying_key,
    ))
}

pub fn verify_public_key_for_verification(
    public_key: &PublicKey,
    debug: bool,
) -> Result<VerifiedPublicKeyForVerification> {
    verify_public_key_for_verification_context(public_key, debug, DEFAULT_PUBLIC_KEY_VERIFY_CONTEXT)
}

pub fn verify_public_key_for_verification_context(
    public_key: &PublicKey,
    debug: bool,
    context: &str,
) -> Result<VerifiedPublicKeyForVerification> {
    let verified_public_key = verify_signing_public_key_context(public_key, debug, context)?;
    let mut warnings = Vec::new();
    if let Some(warning) = build_public_key_expiry_warning(verified_public_key.attested())? {
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
            let attested = verify_public_key_with_attestation_context(
                key,
                debug,
                WORKSPACE_ACTIVE_MEMBER_RECIPIENT_CONTEXT,
            )?;
            enforce_recipient_key_not_expired(&attested)?;
            Ok(VerifiedRecipientKey::new(attested, ExpiryProof::new()))
        })
        .collect()
}

fn log_public_key_verification(
    debug_enabled: bool,
    public_key: &PublicKey,
    context: &str,
    verification_target: &str,
) {
    if debug_enabled {
        debug!(
            "[VERIFY] PublicKey: verify {} ({}, {})",
            verification_target,
            context,
            format_kid_half_display_lossy(&public_key.protected.kid)
        );
    }
}

fn validate_derived_kid(public_key: &PublicKey) -> Result<()> {
    let mut protected_without_kid = serde_json::to_value(&public_key.protected)?;
    let object = protected_without_kid.as_object_mut().ok_or_else(|| {
        Error::build_verification_error(
            "V-KID-DERIVED",
            "PublicKey protected must be a JSON object",
        )
    })?;
    object.remove("kid");

    let derived_kid = derive_public_key_kid(&protected_without_kid)?;
    if public_key.protected.kid != derived_kid {
        return Err(Error::build_verification_error(
            "V-KID-DERIVED",
            format!(
                "PublicKey protected.kid '{}' does not match derived kid '{}'",
                format_kid_display_lossy(&public_key.protected.kid),
                format_kid_display_lossy(&derived_kid)
            ),
        ));
    }

    Ok(())
}

pub(crate) fn build_public_key_expiry_warning(
    doc: &VerifiedPublicKeyAttested,
) -> Result<Option<String>> {
    let doc = doc.document();
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
            sanitize_display_field(&doc.protected.subject_handle),
            days_remaining,
            sanitize_display_field(&expires_at)
        ))),
        KeyExpiryStatus::Expired { expires_at } => Ok(Some(format!(
            "PublicKey for '{}' has expired (expires_at: {})",
            sanitize_display_field(&doc.protected.subject_handle),
            sanitize_display_field(&expires_at)
        ))),
    }
}
