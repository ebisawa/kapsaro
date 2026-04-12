// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust Store document verification (spec §9.6 + §10).

use crate::crypto::sign::verify_trust_store_bytes;
use crate::feature::verify::public_key::{
    verify_public_key_for_verification_context, TRUST_STORE_KEYSTORE_PUBLIC_KEY_CONTEXT,
};
use crate::format::schema::validator::embedded_trust_validator;
use crate::format::trust_store::build_trust_store_signature_bytes;
use crate::io::keystore::storage::load_public_key;
use crate::model::identifiers::alg::SIGNATURE_ED25519;
use crate::model::identifiers::format::TRUST_LOCAL_V2;
use crate::model::public_key::PublicKey;
use crate::model::trust_store::TrustStoreDocument;
use crate::model::trust_store_verified::{TrustStoreVerificationProof, VerifiedTrustStore};
use crate::support::codec::base64_public::decode_base64url_nopad_array;
use crate::{Error, Result};
use ed25519_dalek::VerifyingKey;
use std::collections::HashSet;
use std::path::Path;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Verify a Trust Store document and return a verified wrapper.
///
/// Checks (in order per spec §9.6 + §10):
/// 1. JSON Schema validity
/// 2. signer public key is loaded from local keystore by owner_member_id + kid
/// 3. format == TRUST_LOCAL_V2
/// 4. signer public key is a valid PublicKey
/// 5. Cryptographic signature verification
/// 6. signature.kid == signer_public_key.protected.kid
/// 7. signer_public_key.protected.member_id == protected.owner_member_id
/// 8. known_keys[] kid uniqueness
/// 9. Timestamp format validation (RFC 3339 UTC 'Z')
pub fn verify_trust_store(
    doc: &TrustStoreDocument,
    keystore_root: &Path,
) -> Result<VerifiedTrustStore> {
    validate_schema(doc)?;
    validate_format(doc)?;
    let signer_public_key = load_signer_public_key(doc, keystore_root)?;
    let verifying_key = validate_signer_public_key(&signer_public_key)?;
    validate_signature(doc, &verifying_key)?;
    validate_kid_match(doc, &signer_public_key)?;
    validate_owner_match(doc, &signer_public_key)?;
    validate_known_keys_uniqueness(doc)?;
    validate_timestamps(doc)?;

    let proof = TrustStoreVerificationProof::new(doc.protected.owner_member_id.clone());
    Ok(VerifiedTrustStore::new(doc.clone(), proof))
}

fn validate_schema(doc: &TrustStoreDocument) -> Result<()> {
    let validator = embedded_trust_validator()?;
    let value = serde_json::to_value(doc).map_err(|e| Error::Parse {
        message: format!(
            "Failed to serialize trust store for schema validation: {}",
            e
        ),
        source: Some(Box::new(e)),
    })?;
    validator.validate_trust_store(&value)
}

fn validate_format(doc: &TrustStoreDocument) -> Result<()> {
    if doc.protected.format != TRUST_LOCAL_V2 {
        return Err(Error::Verify {
            rule: "E_TRUST_FORMAT_MISMATCH".to_string(),
            message: format!(
                "Expected format '{}', got '{}'",
                TRUST_LOCAL_V2, doc.protected.format
            ),
        });
    }
    Ok(())
}

fn load_signer_public_key(doc: &TrustStoreDocument, keystore_root: &Path) -> Result<PublicKey> {
    load_public_key(
        keystore_root,
        &doc.protected.owner_member_id,
        &doc.signature.kid,
    )
}

fn validate_signer_public_key(signer_public_key: &PublicKey) -> Result<VerifyingKey> {
    let _verified = verify_public_key_for_verification_context(
        signer_public_key,
        false,
        TRUST_STORE_KEYSTORE_PUBLIC_KEY_CONTEXT,
    )
    .map_err(|e| {
        Error::crypto_with_source("Trust store keystore public key verification failed", e)
    })?;

    let bytes: [u8; 32] = decode_base64url_nopad_array(
        &signer_public_key.protected.identity.keys.sig.x,
        "signer Ed25519 public key",
    )?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| Error::crypto_with_source("Invalid signer Ed25519 key", e))
}

fn validate_signature(doc: &TrustStoreDocument, verifying_key: &VerifyingKey) -> Result<()> {
    let canonical = build_trust_store_signature_bytes(&doc.protected)?;
    verify_trust_store_bytes(&canonical, verifying_key, &doc.signature, SIGNATURE_ED25519)
        .map_err(|e| Error::crypto_with_source("Trust store signature verification failed", e))
}

fn validate_kid_match(doc: &TrustStoreDocument, signer_public_key: &PublicKey) -> Result<()> {
    if doc.signature.kid != signer_public_key.protected.kid {
        return Err(Error::Verify {
            rule: "E_TRUST_KID_MISMATCH".to_string(),
            message: format!(
                "signature.kid '{}' != keystore public key kid '{}'",
                doc.signature.kid, signer_public_key.protected.kid
            ),
        });
    }
    Ok(())
}

fn validate_owner_match(doc: &TrustStoreDocument, signer_public_key: &PublicKey) -> Result<()> {
    if signer_public_key.protected.member_id != doc.protected.owner_member_id {
        return Err(Error::Verify {
            rule: "E_TRUST_OWNER_MISMATCH".to_string(),
            message: format!(
                "keystore public key member_id '{}' != protected.owner_member_id '{}'",
                signer_public_key.protected.member_id, doc.protected.owner_member_id
            ),
        });
    }
    Ok(())
}

fn validate_known_keys_uniqueness(doc: &TrustStoreDocument) -> Result<()> {
    let mut seen_kids = HashSet::new();
    for key in &doc.protected.known_keys {
        if !seen_kids.insert(&key.kid) {
            return Err(Error::Verify {
                rule: "E_TRUST_DUPLICATE_KID".to_string(),
                message: format!("Duplicate kid '{}' in known_keys", key.kid),
            });
        }
    }
    Ok(())
}

fn validate_timestamps(doc: &TrustStoreDocument) -> Result<()> {
    validate_utc_timestamp(&doc.protected.created_at, "created_at")?;
    validate_utc_timestamp(&doc.protected.updated_at, "updated_at")?;
    for key in &doc.protected.known_keys {
        validate_utc_timestamp(&key.approved_at, "known_keys[].approved_at")?;
    }
    Ok(())
}

fn validate_utc_timestamp(ts: &str, field: &str) -> Result<()> {
    if !ts.ends_with('Z') {
        return Err(Error::Verify {
            rule: "E_TRUST_TIMESTAMP_NOT_UTC".to_string(),
            message: format!("{} must end with 'Z' (UTC): '{}'", field, ts),
        });
    }
    OffsetDateTime::parse(ts, &Rfc3339).map_err(|e| Error::Verify {
        rule: "E_TRUST_TIMESTAMP_INVALID".to_string(),
        message: format!(
            "{} must be a valid RFC 3339 UTC timestamp: '{}' ({})",
            field, ts, e
        ),
    })?;
    Ok(())
}
