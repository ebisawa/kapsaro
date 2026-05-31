// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

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
    debug: bool,
) -> Result<String>
where
    V: AsRef<str>,
    F: FnOnce(&mut crate::model::kv_enc::header::KvWrap) -> Result<()>,
{
    let signing = build_signing_context(key_ctx, debug)?;
    super::super::encrypt::encrypt_kv_map_with_wrap_mutation(
        kv_map,
        members,
        &signing,
        token_codec,
        disclosed,
        mutate_wrap,
    )
}
