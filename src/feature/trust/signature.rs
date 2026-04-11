// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust Store document signing.

use crate::crypto::sign::sign_bytes;
use crate::format::trust_store::build_trust_store_signature_bytes;
use crate::model::identifiers::alg::SIGNATURE_ED25519;
use crate::model::trust_store::{TrustStoreDocument, TrustStoreProtected};
use crate::Result;
use ed25519_dalek::SigningKey;

/// Sign a Trust Store protected section and produce a complete document.
pub fn sign_trust_store(
    protected: &TrustStoreProtected,
    signing_key: &SigningKey,
    signer_kid: &str,
) -> Result<TrustStoreDocument> {
    let canonical = build_trust_store_signature_bytes(protected)?;
    // Trust store is a local-only document; verification loads signer key
    // from the local keystore by owner_member_id + kid, not from embedded signer_pub.
    let signature = sign_bytes(&canonical, signing_key, signer_kid, None, SIGNATURE_ED25519)?;
    Ok(TrustStoreDocument {
        protected: protected.clone(),
        signature,
    })
}
