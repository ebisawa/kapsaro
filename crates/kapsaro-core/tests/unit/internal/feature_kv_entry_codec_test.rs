// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `feature::kv::entry_codec::detect_token_codec`.
//! Covers codec detection from a WRAP token and the caller-supplied override.

use crate::feature::kv::entry_codec::detect_token_codec;
use crate::format::token::TokenCodec;

const JCS_WRAP_TOKEN: &str = "jcs-wrap-token";

#[test]
fn test_detect_token_codec_reads_the_codec_from_the_wrap_token() {
    let codec = detect_token_codec(JCS_WRAP_TOKEN, None);

    assert_eq!(codec, TokenCodec::JsonJcs);
}

#[test]
fn test_detect_token_codec_prefers_the_caller_override() {
    let codec = detect_token_codec(JCS_WRAP_TOKEN, Some(TokenCodec::JsonJcs));

    assert_eq!(codec, TokenCodec::JsonJcs);
}
