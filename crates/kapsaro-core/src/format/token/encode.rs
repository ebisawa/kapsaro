// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Token encoding implementation

use crate::format::codec::base64_public::encode_base64url_nopad;
use crate::format::jcs;
use crate::format::token::TokenCodec;
use crate::format::FormatError;
use crate::Result;

/// Serialize value to token.
pub fn to_token_with_codec_impl<T: serde::Serialize>(
    value: &T,
    codec: TokenCodec,
    _debug: bool,
    _label: Option<&str>,
    _caller: Option<&str>,
) -> Result<String> {
    // v3 Rev1: token encoding is JSON/JCS only
    let _ = codec;
    let json_value = serde_json::to_value(value)
        .map_err(|e| crate::Error::from(FormatError::build_json_serialization_error(e)))?;
    let jcs_bytes = jcs::normalize_to_string(&json_value)?;
    let original_bytes = jcs_bytes.as_bytes().to_vec();

    Ok(encode_base64url_nopad(&original_bytes))
}
