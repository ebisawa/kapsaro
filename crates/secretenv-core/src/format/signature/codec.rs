// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Ed25519 artifact signature codec.
//!
//! Encodes and decodes raw 64-byte Ed25519 signatures for wire fields.

use crate::crypto::sign::Ed25519SignatureBytes;
use crate::crypto::{build_crypto_error, build_crypto_operation_error};
use crate::format::codec::base64_public::{decode_base64url_nopad, encode_base64url_nopad};
use crate::Result;

pub(crate) fn encode_ed25519_signature(signature: &Ed25519SignatureBytes) -> String {
    encode_base64url_nopad(signature)
}

pub(crate) fn decode_ed25519_signature(signature: &str) -> Result<Ed25519SignatureBytes> {
    let bytes = decode_base64url_nopad(signature, "signature")
        .map_err(|_| build_crypto_operation_error("Invalid signature Base64"))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        build_crypto_error(
            "Invalid signature length",
            format!("Expected 64 bytes (Ed25519), got {}", bytes.len()),
        )
    })
}
