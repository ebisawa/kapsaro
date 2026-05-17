// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Token codec implementation
//!
//! Provides encode/decode implementations for TokenCodec.

use super::{encode, TokenCodec};
use crate::Result;

impl TokenCodec {
    /// Serialize value to base64url token.
    pub fn encode<T: serde::Serialize>(codec: TokenCodec, value: &T) -> Result<String> {
        encode::to_token_with_codec_impl(value, codec, false, None, None)
    }

    /// Serialize value to token with debug logging.
    pub fn encode_debug<T: serde::Serialize>(
        codec: TokenCodec,
        value: &T,
        debug: bool,
        label: Option<&str>,
        caller: Option<&str>,
    ) -> Result<String> {
        encode::to_token_with_codec_impl(value, codec, debug, label, caller)
    }
}
