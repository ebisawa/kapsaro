// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Envelope artifact signature orchestration.

use crate::crypto::sign::{sign_artifact_bytes, verify_artifact_bytes};
use crate::crypto::types::keys::MasterKey;
use crate::feature::context::crypto::CryptoContext;
use crate::feature::context::expiry::enforce_key_not_expired_for_signing;
use crate::feature::envelope::key_possession::{
    build_file_key_possession_proof, build_key_possession_sig_input, build_kv_key_possession_proof,
};
use crate::format::file::build_file_signature_bytes;
use crate::format::kv::enc::canonical::build_canonical_bytes;
use crate::format::token::TokenCodec;
use crate::io::keystore::signer::load_signer_public_key;
use crate::model::file_enc::FileEncDocumentProtected;
use crate::model::kv_enc::document::KvEncDocument;
use crate::model::public_key::PublicKey;
use crate::model::signature::ArtifactSignature;
use crate::model::wire::algorithm;
use crate::support::kid::format_kid_half_display_lossy;
use crate::Result;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::ops::Deref;
use tracing::debug;

pub struct SigningContext<'a> {
    pub signing_key: &'a SigningKey,
    pub signer_kid: &'a str,
    pub signer_pub: PublicKey,
    pub debug: bool,
}

pub struct VerifiedSigningContext<'a> {
    signing: SigningContext<'a>,
}

impl<'a> VerifiedSigningContext<'a> {
    pub fn signing_key(&self) -> &'a SigningKey {
        self.signing.signing_key
    }

    pub fn signer_kid(&self) -> &'a str {
        self.signing.signer_kid
    }
}

impl<'a> Deref for VerifiedSigningContext<'a> {
    type Target = SigningContext<'a>;

    fn deref(&self) -> &Self::Target {
        &self.signing
    }
}

pub fn build_signing_context<'a>(
    key_ctx: &'a CryptoContext,
    debug: bool,
) -> Result<VerifiedSigningContext<'a>> {
    enforce_key_not_expired_for_signing(&key_ctx.expires_at)?;
    let signer_pub =
        load_signer_public_key(key_ctx.pub_key_source.as_ref(), &key_ctx.member_handle)?;
    Ok(VerifiedSigningContext {
        signing: SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: &key_ctx.kid,
            signer_pub,
            debug,
        },
    })
}

pub fn sign_file_document(
    protected: &FileEncDocumentProtected,
    content_key: &MasterKey,
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
    let canonical_bytes = build_file_signature_bytes(protected)?;
    let mac = build_file_key_possession_proof(protected, content_key, signer_kid)?;
    let sig_input = build_key_possession_sig_input(&canonical_bytes, &mac);
    sign_artifact_bytes(
        &sig_input,
        signing_key,
        signer_kid,
        signer_pub,
        mac,
        algorithm::SIGNATURE_ED25519,
    )
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
    let canonical_bytes = build_file_signature_bytes(protected)?;
    let sig_input = build_key_possession_sig_input(&canonical_bytes, &signature.mac);
    verify_artifact_bytes(
        &sig_input,
        verifying_key,
        signature,
        algorithm::SIGNATURE_ED25519,
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_envelope_signature_test.rs"]
mod tests;

pub(crate) fn sign_kv_document(
    unsigned: &str,
    master_key: &MasterKey,
    signing: &SigningContext<'_>,
    token_codec: TokenCodec,
    caller: &str,
) -> Result<String> {
    append_kv_signature(unsigned, master_key, signing, token_codec, caller)
}

pub(crate) fn append_kv_signature(
    unsigned: &str,
    master_key: &MasterKey,
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
    let mac = build_kv_key_possession_proof(unsigned, master_key, signing.signer_kid)?;
    let sig_input = build_key_possession_sig_input(unsigned.as_bytes(), &mac);
    let signature = sign_artifact_bytes(
        &sig_input,
        signing.signing_key,
        signing.signer_kid,
        signing.signer_pub.clone(),
        mac,
        algorithm::SIGNATURE_ED25519,
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
    let canonical_bytes = build_canonical_bytes(document.lines());
    let sig_input = build_key_possession_sig_input(&canonical_bytes, &signature.mac);
    verify_artifact_bytes(
        &sig_input,
        verifying_key,
        signature,
        algorithm::SIGNATURE_ED25519,
    )
}
