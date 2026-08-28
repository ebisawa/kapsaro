// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Encrypts a KV map back to text as part of a rewrite session.
//! Derives the signing context from the caller's crypto context, then defers to the shared encrypt path.

use crate::feature::context::crypto::build_signing_context;
use crate::feature::context::crypto::CryptoContext;
use crate::format::token::TokenCodec;
use crate::model::public_key::VerifiedRecipientKey;
use crate::Result;
use std::collections::HashMap;

pub(crate) fn encrypt_kv_map_with_key_context<V, F>(
    kv_map: &HashMap<String, V>,
    members: &[VerifiedRecipientKey],
    key_ctx: &CryptoContext,
    token_codec: TokenCodec,
    disclosed: bool,
    mutate_wrap: F,
) -> Result<String>
where
    V: AsRef<str>,
    F: FnOnce(&mut crate::model::kv_enc::header::KvWrap) -> Result<()>,
{
    let signing = build_signing_context(key_ctx)?;
    super::super::encrypt::encrypt_kv_map_with_wrap_mutation(
        kv_map,
        members,
        &signing,
        token_codec,
        disclosed,
        mutate_wrap,
    )
}
