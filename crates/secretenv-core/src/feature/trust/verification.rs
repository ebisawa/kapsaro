// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust Store document verification.

use crate::crypto::sign::verify_detached_bytes;
use crate::feature::trust::recipient_sets::validate_recipient_set_record;
use crate::feature::verify::public_key::{
    verify_public_key_for_verification_context, TRUST_STORE_KEYSTORE_PUBLIC_KEY_CONTEXT,
};
use crate::format::schema::validator::load_embedded_trust_validator;
use crate::format::trust_store::build_trust_store_signature_bytes;
use crate::io::keystore::storage::load_public_key;
use crate::model::public_key::{PublicKey, VerifiedSigningPublicKey};
use crate::model::trust_store::{TrustStoreDocument, TrustStoreSignature};
use crate::model::trust_store_verified::{TrustStoreVerificationProof, VerifiedTrustStore};
use crate::model::wire::algorithm::SIGNATURE_ED25519;
use crate::model::wire::format::LOCAL_TRUST_V5;
use crate::{Error, Result};
use ed25519_dalek::VerifyingKey;
use std::collections::HashSet;
use std::path::Path;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Verify a Trust Store document and return a verified wrapper.
///
/// Checks the trust store signature, signer key, owner, and known key integrity.
/// 1. JSON Schema validity
/// 2. signer public key is loaded from local keystore by owner_handle + kid
/// 3. format == LOCAL_TRUST_V5
/// 4. signer public key is a valid PublicKey
/// 5. Cryptographic signature verification
/// 6. signature.kid == signer_public_key.protected.kid
/// 7. signer_public_key.protected.subject_handle == protected.owner_handle
/// 8. known_keys[] kid uniqueness
/// 9. recipient_sets[] integrity
/// 10. Timestamp format validation (RFC 3339 UTC 'Z')
pub fn verify_trust_store(
    doc: &TrustStoreDocument,
    keystore_root: &Path,
) -> Result<VerifiedTrustStore> {
    validate_schema(doc)?;
    validate_format(doc)?;
    let signer_public_key = load_signer_public_key(doc, keystore_root)?;
    let verified_signer_public_key = validate_signer_public_key(&signer_public_key)?;
    validate_signature(doc, verified_signer_public_key.verifying_key())?;
    validate_kid_match(doc, &signer_public_key)?;
    validate_owner_match(doc, &signer_public_key)?;
    validate_known_keys_uniqueness(doc)?;
    validate_recipient_sets(doc)?;
    validate_timestamps(doc)?;

    let proof = TrustStoreVerificationProof::new(doc.protected.owner_handle.clone());
    Ok(VerifiedTrustStore::new(doc.clone(), proof))
}

fn validate_schema(doc: &TrustStoreDocument) -> Result<()> {
    let validator = load_embedded_trust_validator()?;
    let value = serde_json::to_value(doc).map_err(|e| {
        Error::build_parse_error_with_source(
            format!(
                "Failed to serialize trust store for schema validation: {}",
                e
            ),
            e,
        )
    })?;
    validator.validate_trust_store(&value)
}

fn validate_format(doc: &TrustStoreDocument) -> Result<()> {
    if doc.protected.format != LOCAL_TRUST_V5 {
        return Err(Error::build_verification_error(
            "E_TRUST_FORMAT_MISMATCH".to_string(),
            format!(
                "Expected format '{}', got '{}'",
                LOCAL_TRUST_V5, doc.protected.format
            ),
        ));
    }
    Ok(())
}

fn load_signer_public_key(doc: &TrustStoreDocument, keystore_root: &Path) -> Result<PublicKey> {
    load_public_key(
        keystore_root,
        &doc.protected.owner_handle,
        &doc.signature.kid,
    )
}

fn validate_signer_public_key(signer_public_key: &PublicKey) -> Result<VerifiedSigningPublicKey> {
    verify_public_key_for_verification_context(
        signer_public_key,
        false,
        TRUST_STORE_KEYSTORE_PUBLIC_KEY_CONTEXT,
    )
    .map_err(|e| {
        Error::build_crypto_error_with_source(
            "Trust store keystore public key verification failed",
            e,
        )
    })
    .map(|verified| verified.verified_public_key)
}

fn validate_signature(doc: &TrustStoreDocument, verifying_key: &VerifyingKey) -> Result<()> {
    let canonical = build_trust_store_signature_bytes(&doc.protected)?;
    verify_trust_store_bytes(&canonical, verifying_key, &doc.signature).map_err(|e| {
        Error::build_crypto_error_with_source("Trust store signature verification failed", e)
    })
}

/// Verify trust-store bytes against the wire signature DTO.
pub fn verify_trust_store_bytes(
    canonical_bytes: &[u8],
    verifying_key: &VerifyingKey,
    signature: &TrustStoreSignature,
) -> Result<()> {
    verify_detached_bytes(
        canonical_bytes,
        verifying_key,
        &signature.alg,
        &signature.sig,
        SIGNATURE_ED25519,
    )
}

fn validate_kid_match(doc: &TrustStoreDocument, signer_public_key: &PublicKey) -> Result<()> {
    if doc.signature.kid != signer_public_key.protected.kid {
        return Err(Error::build_verification_error(
            "E_TRUST_KID_MISMATCH".to_string(),
            format!(
                "signature.kid '{}' != keystore public key kid '{}'",
                doc.signature.kid, signer_public_key.protected.kid
            ),
        ));
    }
    Ok(())
}

fn validate_owner_match(doc: &TrustStoreDocument, signer_public_key: &PublicKey) -> Result<()> {
    if signer_public_key.protected.subject_handle != doc.protected.owner_handle {
        return Err(Error::build_verification_error(
            "E_TRUST_OWNER_MISMATCH".to_string(),
            format!(
                "keystore public key member_handle '{}' != protected.owner_handle '{}'",
                signer_public_key.protected.subject_handle, doc.protected.owner_handle
            ),
        ));
    }
    Ok(())
}

fn validate_known_keys_uniqueness(doc: &TrustStoreDocument) -> Result<()> {
    let mut seen_kids = HashSet::new();
    for key in &doc.protected.known_keys {
        if !seen_kids.insert(&key.kid) {
            return Err(Error::build_verification_error(
                "E_TRUST_DUPLICATE_KID".to_string(),
                format!("Duplicate kid '{}' in known_keys", key.kid),
            ));
        }
    }
    Ok(())
}

fn validate_recipient_sets(doc: &TrustStoreDocument) -> Result<()> {
    let mut seen_sids = HashSet::new();
    for record in &doc.protected.recipient_sets {
        if !seen_sids.insert(&record.sid) {
            return Err(Error::build_verification_error(
                "E_RECIPIENT_SET_DUPLICATE_SID".to_string(),
                format!("Duplicate sid '{}' in recipient_sets", record.sid),
            ));
        }
        validate_recipient_set_record(record)?;
    }
    Ok(())
}

fn validate_timestamps(doc: &TrustStoreDocument) -> Result<()> {
    validate_utc_timestamp(&doc.protected.created_at, "created_at")?;
    validate_utc_timestamp(&doc.protected.updated_at, "updated_at")?;
    for key in &doc.protected.known_keys {
        validate_utc_timestamp(&key.approved_at, "known_keys[].approved_at")?;
    }
    for record in &doc.protected.recipient_sets {
        validate_utc_timestamp(&record.approved_at, "recipient_sets[].approved_at")?;
    }
    Ok(())
}

fn validate_utc_timestamp(ts: &str, field: &str) -> Result<()> {
    if !ts.ends_with('Z') {
        return Err(Error::build_verification_error(
            "E_TRUST_TIMESTAMP_NOT_UTC".to_string(),
            format!("{} must end with 'Z' (UTC): '{}'", field, ts),
        ));
    }
    OffsetDateTime::parse(ts, &Rfc3339).map_err(|e| {
        Error::build_verification_error(
            "E_TRUST_TIMESTAMP_INVALID".to_string(),
            format!(
                "{} must be a valid RFC 3339 UTC timestamp: '{}' ({})",
                field, ts, e
            ),
        )
    })?;
    Ok(())
}
