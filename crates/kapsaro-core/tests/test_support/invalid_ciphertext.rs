// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Builds authenticated KV fixtures whose entry ciphertext fails decryption.

use std::collections::HashMap;

use crate::feature::context::crypto::{build_signing_context, CryptoContext};
use crate::feature::envelope::unwrap::unwrap_master_key_for_kv_with_context;
use crate::feature::kv::sign::sign_unsigned_kv_document;
use crate::format::codec::base64_public::{decode_base64url_nopad, encode_base64url_nopad};
use crate::format::kv::document::{parse_kv_document, KvDocumentBuilder};
use crate::format::token::TokenCodec;
use crate::Result;

/// Preserve wraps, MAC validity, and signature validity while corrupting one AEAD ciphertext.
pub fn resign_kv_with_invalid_ciphertext(content: &str, key: &CryptoContext) -> Result<String> {
    let document = parse_kv_document(content)?;
    let master_key = unwrap_master_key_for_kv_with_context(
        &document.head().sid,
        &document.wrap().wrap,
        key.member_handle(),
        key,
    )?;
    let entry = document
        .entries()
        .first()
        .expect("fixture requires an entry");
    let mut value = entry.value().clone();
    let mut ciphertext = decode_base64url_nopad(&value.ct, "fixture ciphertext")?;
    ciphertext[0] ^= 1;
    value.ct = encode_base64url_nopad(&ciphertext);
    let token = TokenCodec::encode(TokenCodec::JsonJcs, &value)?;
    let mut unsigned = KvDocumentBuilder::from_document(
        document.head().clone(),
        None,
        &document,
        TokenCodec::JsonJcs,
    )?
    .build();
    unsigned.set_entries(&HashMap::from([(entry.key(), token.as_str())]));
    let signing = build_signing_context(key)?;
    sign_unsigned_kv_document(unsigned, &master_key.value, &signing)
}
