// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KEM key material extraction for verified private-key contexts.
//! Keeps wire decoding near CryptoContext instead of the crypto primitive layer.

use crate::crypto::kem::X25519SecretKey;
use crate::format::codec::base64_secret::decode_base64url_nopad_secret_32;
use crate::model::verified::VerifiedPrivateKey;
use crate::Result;

/// Decode KEM secret key from a verified private-key document.
pub fn decode_kem_secret_key(private_key: &VerifiedPrivateKey) -> Result<X25519SecretKey> {
    let kem_sk_bytes =
        decode_base64url_nopad_secret_32(&private_key.document().keys.kem.d, "KEM private key")?;
    Ok(X25519SecretKey::from_zeroizing(
        kem_sk_bytes.into_zeroizing(),
    ))
}
