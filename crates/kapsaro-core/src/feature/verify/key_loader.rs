// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key loading for signature verification.

use crate::model::public_key::PublicKey;
use crate::model::signature::ArtifactSignature;
use crate::model::verification::VerifyingKeySource;
use crate::support::kid::format_kid_display_lossy;
use crate::{Error, Result};
use ed25519_dalek::VerifyingKey;

use super::public_key::{verify_public_key_for_verification_context, EMBEDDED_SIGNER_PUB_CONTEXT};

/// Result of loading a verifying key from a signature
#[derive(Debug)]
pub struct SignatureVerificationKey {
    pub verifying_key: VerifyingKey,
    pub member_handle: String,
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
) -> Result<SignatureVerificationKey> {
    build_loaded_verifying_key(
        &signature.signer_pub,
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
) -> Result<SignatureVerificationKey> {
    let verified =
        verify_public_key_for_verification_context(public_key, debug, EMBEDDED_SIGNER_PUB_CONTEXT)
            .map_err(|e| {
                Error::build_crypto_error_with_source(
                    format!("PublicKey document verification failed ({})", source_label),
                    e,
                )
            })?;

    let doc = verified.verified_public_key.document();
    if expected_kid != doc.protected.kid {
        return Err(Error::build_crypto_error(format!(
            "kid mismatch: signature.kid '{}' != signer_pub.protected.kid '{}'",
            format_kid_display_lossy(expected_kid),
            format_kid_display_lossy(&doc.protected.kid)
        )));
    }

    Ok(SignatureVerificationKey {
        verifying_key: *verified.verified_public_key.verifying_key(),
        member_handle: doc.protected.subject_handle.clone(),
        source,
        warnings: verified.warnings,
        public_key: public_key.clone(),
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_verify_key_loader_internal_test.rs"]
mod internal_tests;

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_verify_key_loader_test.rs"]
mod feature_verify_key_loader_test;
