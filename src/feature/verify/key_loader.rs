// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key loading for signature verification.

use crate::model::public_key::PublicKey;
use crate::model::signature::ArtifactSignature;
use crate::model::verification::VerifyingKeySource;
use crate::support::codec::base64_public::decode_base64url_nopad_array;
use crate::support::kid::kid_display_lossy;
use crate::{Error, Result};
use ed25519_dalek::VerifyingKey;

use super::public_key::verify_public_key_for_verification;

/// Result of loading a verifying key from a signature
#[derive(Debug)]
pub struct LoadedVerifyingKey {
    pub verifying_key: VerifyingKey,
    pub member_id: String,
    pub source: VerifyingKeySource,
    pub warnings: Vec<String>,
    pub public_key: PublicKey,
}

/// Load verifying key from signature's embedded signer_pub.
///
/// Expired keys are allowed for verification but generate a warning.
pub fn load_verifying_key_from_signature(
    signature: &ArtifactSignature,
    debug: bool,
) -> Result<LoadedVerifyingKey> {
    load_from_signer_pub(signature, &signature.signer_pub, debug)
}

/// Load verifying key from embedded signer_pub.
fn load_from_signer_pub(
    signature: &ArtifactSignature,
    signer_pub: &PublicKey,
    debug: bool,
) -> Result<LoadedVerifyingKey> {
    build_loaded_verifying_key(
        signer_pub,
        &signature.kid,
        VerifyingKeySource::SignerPubEmbedded,
        "signer_pub embedded",
        debug,
    )
}

fn build_loaded_verifying_key(
    public_key: &PublicKey,
    expected_kid: &str,
    source: VerifyingKeySource,
    source_label: &str,
    debug: bool,
) -> Result<LoadedVerifyingKey> {
    let verified = verify_public_key_for_verification(public_key, debug).map_err(|e| {
        Error::crypto_with_source(
            format!("PublicKey document verification failed ({})", source_label),
            e,
        )
    })?;

    let doc = verified.verified_public_key.document();
    if expected_kid != doc.protected.kid {
        return Err(Error::Crypto {
            message: format!(
                "kid mismatch: signature.kid '{}' != signer_pub.protected.kid '{}'",
                kid_display_lossy(expected_kid),
                kid_display_lossy(&doc.protected.kid)
            ),
            source: None,
        });
    }

    Ok(LoadedVerifyingKey {
        verifying_key: extract_verifying_key(doc)?,
        member_id: doc.protected.member_id.clone(),
        source,
        warnings: verified.warnings,
        public_key: public_key.clone(),
    })
}

/// Extract Ed25519 verifying key from a PublicKey document.
fn extract_verifying_key(doc: &PublicKey) -> Result<VerifyingKey> {
    let verifying_key_bytes: [u8; 32] =
        decode_base64url_nopad_array(&doc.protected.identity.keys.sig.x, "Ed25519 public key")?;
    VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|e| Error::crypto_with_source("Invalid Ed25519 public key", e))
}

#[cfg(test)]
#[path = "../../../tests/unit/feature_verify_key_loader_internal_test.rs"]
mod tests;
