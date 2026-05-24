// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV-enc wire format writer — assembles unsigned KV-enc document strings.

use crate::format::kv::HEADER_LINE_V9;

/// Build an unsigned KV-enc document string from pre-encoded tokens.
///
/// This function performs pure string assembly — all encoding must be
/// completed by the caller. The result is infallible.
pub fn build_unsigned_kv_document(
    head_token: &str,
    wrap_token: &str,
    entries: &[(&str, &str)],
) -> String {
    let mut out = String::new();
    out.push_str(HEADER_LINE_V9);
    out.push('\n');
    out.push_str(&format!(":HEAD {}\n", head_token));
    out.push_str(&format!(":WRAP {}\n", wrap_token));
    for &(key, token) in entries {
        out.push_str(&format!("{} {}\n", key, token));
    }
    out
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/format_kv_enc_writer_test.rs"]
mod tests;
