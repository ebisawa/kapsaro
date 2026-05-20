// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Verify feature - signature verification.

pub mod file;
pub mod kv;
pub mod private_key;
pub mod public_key;
pub mod recipients;

pub mod key_loader;
pub(crate) mod report;
pub(crate) mod signature;

use crate::feature::context::expiry::enforce_expired_key_usage;
use crate::model::public_key::PublicKey;
use crate::model::verification::{SignatureVerificationProof, VerifyingKeySource};
use crate::Result;

/// Report of signature verification result
#[derive(Debug, Clone)]
pub struct SignatureVerificationReport {
    /// Whether verification succeeded
    pub verified: bool,
    /// Signer's member_handle (if successfully identified)
    pub signer_handle: Option<String>,
    /// Source of the verifying key
    pub source: Option<VerifyingKeySource>,
    /// Warnings (e.g., expired key)
    pub warnings: Vec<String>,
    /// Human-readable message (success or failure reason)
    pub message: String,
    /// Signer's PublicKey (available when verification succeeds)
    pub signer_public_key: Option<PublicKey>,
}

pub(crate) fn append_operational_signer_expiry_warning(
    proof: &mut SignatureVerificationProof,
    allow_expired_key: bool,
) -> Result<()> {
    let Some(signer) = &proof.signer_public_key else {
        return Ok(());
    };
    let expires_at = &signer.protected.expires_at;
    if expires_at.is_empty() {
        return Ok(());
    }
    if let Some(warning) =
        enforce_expired_key_usage(expires_at, allow_expired_key, "Artifact signing key")?
    {
        push_unique_warning(&mut proof.warnings, warning);
    }
    Ok(())
}

fn push_unique_warning(warnings: &mut Vec<String>, warning: String) {
    if !warnings.contains(&warning) {
        warnings.push(warning);
    }
}
