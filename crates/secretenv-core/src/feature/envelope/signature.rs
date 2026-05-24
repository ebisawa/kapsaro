// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Envelope artifact signature orchestration.

use crate::crypto::sign::{sign_detached_bytes, verify_detached_bytes};
use crate::crypto::types::keys::MacKey;
use crate::feature::context::crypto::SigningContext;
use crate::feature::envelope::key_possession::{
    build_file_key_possession_proof, build_kv_key_possession_proof,
};
use crate::format::signature::{
    build_artifact_signature_input, build_file_artifact_body_bytes, build_kv_artifact_body_bytes,
    build_kv_artifact_body_bytes_from_unsigned, decode_ed25519_signature, encode_ed25519_signature,
    verify_signature_algorithm,
};
use crate::format::token::TokenCodec;
use crate::model::file_enc::FileEncDocumentProtected;
use crate::model::kv_enc::document::KvEncDocument;
use crate::model::public_key::PublicKey;
use crate::model::signature::ArtifactSignature;
use crate::model::wire::algorithm;
use crate::support::kid::format_kid_half_display_lossy;
use crate::Result;
use ed25519_dalek::{SigningKey, VerifyingKey};
use tracing::debug;

pub fn sign_file_document(
    protected: &FileEncDocumentProtected,
    mac_key: &MacKey,
    signing_key: &SigningKey,
    signer_kid: &str,
    signer_pub: PublicKey,
    debug: bool,
) -> Result<ArtifactSignature> {
    if debug {
        debug!(
            "[CRYPTO] Ed25519: sign_artifact_bytes (kid: {})",
            format_kid_half_display_lossy(signer_kid)
        );
    }
    let body_bytes = build_file_artifact_body_bytes(protected)?;
    let mac = build_file_key_possession_proof(&body_bytes, mac_key, signer_kid, debug)?;
    let sig_input = build_artifact_signature_input(
        algorithm::SIGNATURE_ED25519,
        signer_kid,
        &body_bytes,
        mac.as_str(),
    )?;
    build_artifact_signature(&sig_input, signing_key, signer_kid, signer_pub, mac)
}

pub fn verify_file_signature(
    protected: &FileEncDocumentProtected,
    verifying_key: &VerifyingKey,
    signature: &ArtifactSignature,
    debug: bool,
) -> Result<()> {
    if debug {
        debug!(
            "[VERIFY] Ed25519: verify_artifact_bytes (kid: {})",
            format_kid_half_display_lossy(&signature.kid)
        );
    }
    let body_bytes = build_file_artifact_body_bytes(protected)?;
    let sig_input = build_artifact_signature_input(
        signature.alg.as_str(),
        signature.kid.as_str(),
        &body_bytes,
        signature.mac.as_str(),
    )?;
    verify_signature_algorithm(&signature.alg, algorithm::SIGNATURE_ED25519)?;
    let signature_bytes = decode_ed25519_signature(&signature.sig)?;
    verify_detached_bytes(&sig_input, verifying_key, &signature_bytes)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_envelope_signature_test.rs"]
mod tests;

pub(crate) fn sign_kv_document(
    unsigned: &str,
    mac_key: &MacKey,
    signing: &SigningContext<'_>,
    token_codec: TokenCodec,
    caller: &str,
) -> Result<String> {
    append_kv_signature(unsigned, mac_key, signing, token_codec, caller)
}

fn append_kv_signature(
    unsigned: &str,
    mac_key: &MacKey,
    signing: &SigningContext<'_>,
    token_codec: TokenCodec,
    caller: &str,
) -> Result<String> {
    if signing.debug {
        debug!(
            "[CRYPTO] Ed25519: sign_artifact_bytes (kid: {})",
            format_kid_half_display_lossy(signing.signer_kid)
        );
    }
    let body_bytes = build_kv_artifact_body_bytes_from_unsigned(unsigned);
    let mac =
        build_kv_key_possession_proof(&body_bytes, mac_key, signing.signer_kid, signing.debug)?;
    let sig_input = build_artifact_signature_input(
        algorithm::SIGNATURE_ED25519,
        signing.signer_kid,
        &body_bytes,
        mac.as_str(),
    )?;
    let signature = build_artifact_signature(
        &sig_input,
        signing.signing_key,
        signing.signer_kid,
        signing.signer_pub.clone(),
        mac,
    )?;
    let sig_token = TokenCodec::encode_debug(
        token_codec,
        &signature,
        signing.debug,
        Some("SIG"),
        Some(caller),
    )?;
    Ok(format!("{}:SIG {}\n", unsigned, sig_token))
}

pub fn verify_kv_signature(
    document: &KvEncDocument,
    verifying_key: &VerifyingKey,
    signature: &ArtifactSignature,
    debug: bool,
) -> Result<()> {
    if debug {
        debug!(
            "[VERIFY] Ed25519: verify_artifact_bytes (kid: {})",
            format_kid_half_display_lossy(&signature.kid)
        );
    }
    let body_bytes = build_kv_artifact_body_bytes(document);
    let sig_input = build_artifact_signature_input(
        signature.alg.as_str(),
        signature.kid.as_str(),
        &body_bytes,
        signature.mac.as_str(),
    )?;
    verify_signature_algorithm(&signature.alg, algorithm::SIGNATURE_ED25519)?;
    let signature_bytes = decode_ed25519_signature(&signature.sig)?;
    verify_detached_bytes(&sig_input, verifying_key, &signature_bytes)
}

fn build_artifact_signature(
    sig_input: &[u8],
    signing_key: &SigningKey,
    signer_kid: &str,
    signer_pub: PublicKey,
    mac: crate::model::signature::KeyPossessionProof,
) -> Result<ArtifactSignature> {
    let sig = encode_ed25519_signature(&sign_detached_bytes(sig_input, signing_key)?);
    Ok(ArtifactSignature {
        alg: algorithm::SIGNATURE_ED25519.to_string(),
        kid: signer_kid.to_string(),
        signer_pub,
        mac,
        sig,
    })
}
