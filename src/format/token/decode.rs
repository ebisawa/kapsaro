// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Token decoding implementation.

use crate::format::token::TokenCodec;
use crate::format::FormatError;
use crate::support::codec::base64_public::decode_base64url_nopad_token;
use crate::Result;

/// Decode a token's raw bytes.
/// Returns (bytes, codec).
pub fn decode_token_bytes(
    token: &str,
    _debug: bool,
    _caller: Option<&str>,
) -> Result<(Vec<u8>, TokenCodec)> {
    // CBOR tokens were supported in earlier versions but are removed in the current spec.
    if token.starts_with("cb:") || token.starts_with("cz:") {
        return Err(FormatError::build_parse_error(
            "CBOR tokens are not supported (use JSON/JCS tokens)",
        )
        .into());
    }

    let data = decode_base64url_nopad_token(token, "token")?;
    Ok((data, TokenCodec::JsonJcs))
}
