// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Envelope signature orchestration.

use crate::crypto::sign::{sign_bytes, verify_bytes};
use crate::feature::context::crypto::CryptoContext;
use crate::feature::context::expiry::enforce_key_not_expired_for_signing;
use crate::format::file::build_file_signature_bytes;
use crate::format::kv::enc::canonical::build_canonical_bytes;
use crate::format::token::TokenCodec;
use crate::io::keystore::signer::load_signer_public_key;
use crate::model::file_enc::FileEncDocumentProtected;
use crate::model::identifiers::alg;
use crate::model::kv_enc::document::KvEncDocument;
use crate::model::public_key::PublicKey;
use crate::model::signature::Signature;
use crate::support::kid::build_kid_display;
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

    pub fn signer_pub(&self) -> PublicKey {
        self.signing.signer_pub.clone()
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
    let signer_pub = load_signer_public_key(key_ctx.pub_key_source.as_ref(), &key_ctx.member_id)?;
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
    signing_key: &SigningKey,
    signer_kid: &str,
    signer_pub: PublicKey,
    debug: bool,
) -> Result<Signature> {
    if debug {
        let kid_display = build_kid_display(signer_kid).unwrap_or_else(|_| signer_kid.to_string());
        debug!("[CRYPTO] Ed25519: sign_bytes (kid: {})", kid_display);
    }
    let canonical_bytes = build_file_signature_bytes(protected)?;
    sign_bytes(
        &canonical_bytes,
        signing_key,
        signer_kid,
        Some(signer_pub),
        alg::SIGNATURE_ED25519,
    )
}

pub fn verify_file_signature(
    protected: &FileEncDocumentProtected,
    verifying_key: &VerifyingKey,
    signature: &Signature,
    debug: bool,
) -> Result<()> {
    if debug {
        let kid_display =
            build_kid_display(&signature.kid).unwrap_or_else(|_| signature.kid.clone());
        debug!("[VERIFY] Ed25519: verify_bytes (kid: {})", kid_display);
    }
    let canonical_bytes = build_file_signature_bytes(protected)?;
    verify_bytes(
        &canonical_bytes,
        verifying_key,
        signature,
        alg::SIGNATURE_ED25519,
    )
}

pub(crate) fn sign_kv_document(
    unsigned: &str,
    signing: &SigningContext<'_>,
    token_codec: TokenCodec,
    caller: &str,
) -> Result<String> {
    sign_and_append_kv_sig(
        unsigned,
        signing.signing_key,
        signing.signer_kid,
        signing.signer_pub.clone(),
        token_codec,
        signing.debug,
        caller,
    )
}

pub(crate) fn sign_and_append_kv_sig(
    unsigned: &str,
    signing_key: &SigningKey,
    signer_kid: &str,
    signer_pub: PublicKey,
    token_codec: TokenCodec,
    debug: bool,
    caller: &str,
) -> Result<String> {
    if debug {
        let kid_display = build_kid_display(signer_kid).unwrap_or_else(|_| signer_kid.to_string());
        debug!("[CRYPTO] Ed25519: sign_bytes (kid: {})", kid_display);
    }
    let signature = sign_bytes(
        unsigned.as_bytes(),
        signing_key,
        signer_kid,
        Some(signer_pub),
        alg::SIGNATURE_ED25519,
    )?;
    let sig_token =
        TokenCodec::encode_debug(token_codec, &signature, debug, Some("SIG"), Some(caller))?;
    Ok(format!("{}:SIG {}\n", unsigned, sig_token))
}

pub fn verify_kv_signature(
    document: &KvEncDocument,
    verifying_key: &VerifyingKey,
    signature: &Signature,
    debug: bool,
) -> Result<()> {
    if debug {
        let kid_display =
            build_kid_display(&signature.kid).unwrap_or_else(|_| signature.kid.clone());
        debug!("[VERIFY] Ed25519: verify_bytes (kid: {})", kid_display);
    }
    let canonical_bytes = build_canonical_bytes(document.lines());
    verify_bytes(
        &canonical_bytes,
        verifying_key,
        signature,
        alg::SIGNATURE_ED25519,
    )
}

#[cfg(test)]
#[path = "../../../tests/unit/feature_envelope_signature_test.rs"]
mod tests;
