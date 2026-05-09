// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `feature::kv::entry_codec::detect_token_codec`.
//!
//! The function relies on the invariant that `KvEncDocument` is only
//! constructed via `parse_kv_document`, which enforces the presence of a
//! `:WRAP` line. These tests exercise the WRAP lookup and the override path
//! to pin down that behavior and guard against the `.expect(...)` regressing
//! into a reachable panic.

use crate::feature::kv::entry_codec::detect_token_codec;
use crate::format::token::TokenCodec;
use crate::model::kv_enc::line::{KvEncLine, KvEncVersion};

fn wrap_line() -> KvEncLine {
    KvEncLine::Wrap {
        token: "jcs-wrap-token".to_string(),
    }
}

fn header_line() -> KvEncLine {
    KvEncLine::Header {
        version: KvEncVersion::V6,
    }
}

fn head_line() -> KvEncLine {
    KvEncLine::Head {
        token: "head-token".to_string(),
    }
}

#[test]
fn test_detect_token_codec_returns_codec_from_wrap_line() {
    let lines = vec![header_line(), head_line(), wrap_line()];

    let codec = detect_token_codec(&lines, None);

    assert_eq!(codec, TokenCodec::JsonJcs);
}

#[test]
fn test_detect_token_codec_override_bypasses_wrap_lookup() {
    // No WRAP line in the input. If the function attempted the lookup
    // the embedded `.expect(...)` would panic; the override path must
    // short-circuit before that happens.
    let lines = vec![header_line(), head_line()];

    let codec = detect_token_codec(&lines, Some(TokenCodec::JsonJcs));

    assert_eq!(codec, TokenCodec::JsonJcs);
}

#[test]
fn test_detect_token_codec_finds_wrap_in_non_first_position() {
    // The WRAP line is neither first nor last; the scan must still locate it.
    let lines = vec![
        header_line(),
        head_line(),
        wrap_line(),
        KvEncLine::KV {
            key: "K".to_string(),
            token: "kv-token".to_string(),
        },
    ];

    let codec = detect_token_codec(&lines, None);

    assert_eq!(codec, TokenCodec::JsonJcs);
}
