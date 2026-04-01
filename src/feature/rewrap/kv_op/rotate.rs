// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Rotate master key for kv-enc content.

use crate::feature::context::crypto::CryptoContext;
use crate::format::kv::detect_token_codec_from_kv_content;
use crate::format::kv::enc::canonical::{extract_recipients_from_wrap, parse_kv_wrap};
use crate::format::schema::document::parse_kv_entry_token;
use crate::model::kv_enc::line::KvEncLine;
use crate::Result;

use super::reencrypt::{decrypt_kv_content, encrypt_kv_with_recipients};

/// Detect if any KV entry in the content has the `disclosed` flag set.
fn detect_disclosed_entries(content: &str) -> Result<bool> {
    let (lines, _, _) = parse_kv_wrap(content)?;
    Ok(lines.iter().any(|line| {
        if let KvEncLine::KV { token, .. } = line {
            parse_kv_entry_token(token.as_str())
                .map(|entry| entry.disclosed)
                .unwrap_or(false)
        } else {
            false
        }
    }))
}

/// Rotate master key for kv-enc content.
pub fn rotate_kv_key(content: &str, key_ctx: &CryptoContext, debug: bool) -> Result<String> {
    let disclosed = detect_disclosed_entries(content)?;
    let decrypted = decrypt_kv_content(content, key_ctx, debug)?;
    let (_, _, wrap_data) = parse_kv_wrap(content)?;
    let current_recipients = extract_recipients_from_wrap(&wrap_data);
    let token_codec = detect_token_codec_from_kv_content(content);
    encrypt_kv_with_recipients(
        &decrypted,
        &current_recipients,
        key_ctx,
        token_codec,
        disclosed,
        debug,
    )
}
