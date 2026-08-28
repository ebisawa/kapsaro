// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Verified signing context construction.
//! Owns key-expiry enforcement and signer public-key loading for write operations.

use std::ops::Deref;

use ed25519_dalek::SigningKey;

use crate::feature::verify::public_key::{
    verify_public_key_with_attestation_context, KEYSTORE_SIBLING_PUBLIC_KEY_CONTEXT,
};
use crate::io::keystore::signer::load_signer_public_key;
use crate::model::identity::Kid;
use crate::model::public_key::PublicKey;
use crate::{Error, Result};

use super::CryptoContext;

pub struct SigningContext<'a> {
    pub signing_key: &'a SigningKey,
    pub signer_kid: &'a str,
    pub signer_pub: PublicKey,
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

/// Build the context a write signs with, from the key the context holds.
///
/// The signer public key is embedded in the artifact and is what every reader
/// verifies the signature against, so it is put through the same full check a
/// reader applies — derived key id, self-signature, and attestation — before it
/// is used. Signing a document around a key statement readers reject would
/// produce an artifact nobody can open.
pub fn build_signing_context(key_ctx: &CryptoContext) -> Result<VerifiedSigningContext<'_>> {
    key_ctx.enforce_signing_key_not_expired()?;
    let signer_kid = Kid::try_from(key_ctx.kid())?;
    let signer_pub = load_signer_public_key(
        key_ctx.pub_key_source.as_ref(),
        key_ctx.member_handle_id(),
        &signer_kid,
    )?;
    verify_public_key_with_attestation_context(&signer_pub, KEYSTORE_SIBLING_PUBLIC_KEY_CONTEXT)?;
    ensure_signer_public_key_matches_signing_key(key_ctx, &signer_pub)?;
    Ok(VerifiedSigningContext {
        signing: SigningContext {
            signing_key: key_ctx.signing_key(),
            signer_kid: key_ctx.kid(),
            signer_pub,
        },
    })
}

/// Require the embedded signer public key to be the public half of the key that
/// signs, under the key id the signature names.
///
/// A verifier reads the signature against this document, so a key naming
/// another member, another key id, or another Ed25519 public point would leave
/// a signature nobody can verify, or one attributed to a key it was never made
/// with. The signing key and the key it claims to be are settled together here
/// rather than left to disagree.
fn ensure_signer_public_key_matches_signing_key(
    key_ctx: &CryptoContext,
    signer_pub: &PublicKey,
) -> Result<()> {
    if key_ctx
        .local_key_identity()
        .matches_public_key(signer_pub)?
    {
        return Ok(());
    }
    Err(Error::build_verification_error(
        "V-SIGNER-KEY-BINDING".to_string(),
        format!(
            "Stored signer public key '{}' is not the public half of the key loaded for '{}' as '{}'",
            signer_pub.protected.kid,
            key_ctx.member_handle(),
            key_ctx.kid()
        ),
    ))
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/feature_context_crypto_signing_test.rs"]
mod feature_context_crypto_signing_test;
