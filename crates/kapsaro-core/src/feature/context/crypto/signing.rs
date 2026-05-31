// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Verified signing context construction.
//! Owns key-expiry enforcement and signer public-key loading for write operations.

use std::ops::Deref;

use ed25519_dalek::SigningKey;

use crate::feature::context::expiry::enforce_key_not_expired_for_signing;
use crate::io::keystore::signer::load_signer_public_key;
use crate::model::public_key::PublicKey;
use crate::Result;

use super::CryptoContext;

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
    key_ctx.enforce_signing_key_not_expired()?;
    let signer_pub =
        load_signer_public_key(key_ctx.pub_key_source.as_ref(), key_ctx.member_handle_id())?;
    Ok(VerifiedSigningContext {
        signing: SigningContext {
            signing_key: key_ctx.signing_key(),
            signer_kid: key_ctx.kid(),
            signer_pub,
            debug,
        },
    })
}
