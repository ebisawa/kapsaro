// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key loading for signature verification.

use crate::io::workspace::members::find_active_member_by_kid;
use crate::model::public_key::PublicKey;
use crate::model::signature::Signature;
use crate::model::verification::VerifyingKeySource;
use crate::support::base64url::b64_decode_array;
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
/// If signer_pub is missing, fails with E_SIGNER_PUB_MISSING.
pub fn load_verifying_key_from_signature(
    signature: &Signature,
    workspace_path: Option<&std::path::Path>,
    debug: bool,
) -> Result<LoadedVerifyingKey> {
    let signer_pub = signature.signer_pub.as_ref().ok_or_else(|| Error::Verify {
        rule: "E_SIGNER_PUB_MISSING".to_string(),
        message: "Required signer_pub is missing from signature".to_string(),
    })?;
    load_from_signer_pub(signature, signer_pub, workspace_path, debug)
}

/// Load verifying key from embedded signer_pub.
///
/// The embedded key is used for cryptographic verification, but membership
/// is also confirmed by checking that the kid exists in workspace active members.
fn load_from_signer_pub(
    signature: &Signature,
    signer_pub: &PublicKey,
    workspace_path: Option<&std::path::Path>,
    debug: bool,
) -> Result<LoadedVerifyingKey> {
    verify_kid_in_active_members(workspace_path, &signature.kid)?;
    build_loaded_verifying_key(
        signer_pub,
        &signature.kid,
        VerifyingKeySource::SignerPubEmbedded,
        "signer_pub embedded",
        debug,
    )
}

/// Verify that a kid exists in workspace active members.
fn verify_kid_in_active_members(workspace_path: Option<&std::path::Path>, kid: &str) -> Result<()> {
    let ws_path = workspace_path.ok_or_else(|| Error::Crypto {
        message: "Workspace is required to verify signer membership".to_string(),
        source: None,
    })?;
    let found = find_active_member_by_kid(ws_path, kid)?;
    if found.is_none() {
        return Err(Error::Crypto {
            message: format!(
                "Signer key '{}' not found in active members",
                kid_display_lossy(kid)
            ),
            source: None,
        });
    }
    Ok(())
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
        b64_decode_array(&doc.protected.identity.keys.sig.x, "Ed25519 public key")?;
    VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|e| Error::crypto_with_source("Invalid Ed25519 public key", e))
}

#[cfg(test)]
#[path = "../../../tests/unit/feature_verify_key_loader_internal_test.rs"]
mod tests;
