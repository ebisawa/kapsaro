// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for format/token/encode module
//!
//! Tests for token encoding.

use secretenv::format::token::TokenCodec;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TestData {
    message: String,
    count: u32,
}

#[test]
fn test_token_encode() {
    let data = TestData {
        message: "test".to_string(),
        count: 42,
    };

    let token = TokenCodec::encode(TokenCodec::JsonJcs, &data).unwrap();

    assert!(!token.is_empty());
    // Should be base64url encoded
    assert!(!token.contains(" "));
}

#[test]
fn test_token_encode_debug() {
    let data = TestData {
        message: "test".to_string(),
        count: 42,
    };

    let token = TokenCodec::encode_debug(
        TokenCodec::JsonJcs,
        &data,
        true,
        Some("test"),
        Some("test_token_encode_debug"),
    )
    .unwrap();

    assert!(!token.is_empty());
}

#[test]
fn test_token_encode_large_data() {
    let data = TestData {
        message: "A".repeat(1000),
        count: 42,
    };

    let token = TokenCodec::encode(TokenCodec::JsonJcs, &data).unwrap();

    assert!(!token.is_empty());
}
