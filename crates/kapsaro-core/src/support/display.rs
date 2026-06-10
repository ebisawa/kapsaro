// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Display-only sanitization helpers.
//!
//! These helpers are intended **only** for human-facing display strings in logs and errors.
//! They must not be used for cryptographic verification, comparisons, or as part of signed data.

const DEFAULT_MAX_LEN: usize = 200;

pub fn sanitize_display_field(value: &str) -> String {
    sanitize_display_field_with_limit(value, DEFAULT_MAX_LEN)
}

pub fn sanitize_display_field_with_limit(value: &str, max_len: usize) -> String {
    let max_len = max_len.max(8);

    let mut out = String::with_capacity(value.len().min(max_len));
    for ch in value.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push('?'),
            c => out.push(c),
        }

        if out.len() >= max_len {
            out.push('…');
            break;
        }
    }
    out
}

#[cfg(test)]
#[path = "../../tests/unit/internal/support_display_sanitize_test.rs"]
mod support_display_sanitize_test;
