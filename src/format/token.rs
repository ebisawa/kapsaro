// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Token encoding/decoding (base64url).
//!
//! This module provides a generic token API (`TokenCodec`) for encoding/decoding
//! structured data into compact tokens:
//! - JCS-normalized JSON (RFC 8785)
//!
//! NOTE: v3 Rev9 currently supports JSON/JCS only. The enum-based codec API is
//! designed to keep the call sites independent from the underlying format module
//! (e.g. `format/jcs`).

mod codec;
mod decode;
mod encode;

/// Token codec type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenCodec {
    /// JSON/JCS encoding (RFC 8785)
    JsonJcs,
}

impl TokenCodec {
    /// Detect codec from token string prefix.
    ///
    /// v3 Rev9: token encoding is JSON/JCS only.
    pub fn detect(token: &str) -> Self {
        let _ = token;
        TokenCodec::JsonJcs
    }
}

pub(crate) use decode::decode_token_bytes;
