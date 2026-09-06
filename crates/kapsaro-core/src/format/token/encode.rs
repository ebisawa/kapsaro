// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Token encoding implementation

use crate::format::codec::base64_public::encode_base64url_nopad;
use crate::format::jcs;
use crate::format::token::TokenCodec;
use crate::Result;

/// Serialize value to token.
pub fn to_token_with_codec_impl<T: serde::Serialize>(
    value: &T,
    codec: TokenCodec,
) -> Result<String> {
    // v3 Rev1: token encoding is JSON/JCS only
    let _ = codec;
    let jcs_bytes = jcs::normalize(value)?;
    Ok(encode_base64url_nopad(&jcs_bytes))
}
