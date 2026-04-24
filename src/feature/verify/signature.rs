// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for signed document verification.

use crate::model::signature::ArtifactSignature;
use crate::model::verification::SignatureVerificationProof;
use crate::Result;

use super::key_loader::{load_verifying_key_from_signature, SignatureVerificationKey};

pub(crate) fn verify_signature_with_loaded_key<Verify>(
    signature: &ArtifactSignature,
    debug: bool,
    verify: Verify,
) -> Result<SignatureVerificationProof>
where
    Verify: FnOnce(&SignatureVerificationKey) -> Result<()>,
{
    let loaded = load_verifying_key_from_signature(signature, debug)?;
    verify(&loaded)?;
    Ok(build_signature_verification_proof(signature, loaded))
}

fn build_signature_verification_proof(
    signature: &ArtifactSignature,
    loaded: SignatureVerificationKey,
) -> SignatureVerificationProof {
    SignatureVerificationProof::new_with_signer_public_key(
        loaded.member_id,
        signature.kid.clone(),
        loaded.public_key,
        loaded.source,
        loaded.warnings,
    )
}
