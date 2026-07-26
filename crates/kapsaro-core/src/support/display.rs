// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Display-only sanitization helpers.
//!
//! These helpers are intended **only** for human-facing display strings in logs and errors.
//! They must not be used for cryptographic verification, comparisons, or as part of signed data.

const DEFAULT_MAX_LEN: usize = 200;
const MIN_MAX_LEN: usize = 8;
const TRUNCATION_MARK: char = '\u{2026}';

pub fn sanitize_display_field(value: &str) -> String {
    sanitize_display_field_with_limit(value, DEFAULT_MAX_LEN)
}

/// Escape control characters and truncate on a character boundary.
///
/// `max_len` bounds the escaped output in bytes. The truncation mark is
/// appended only when input characters were actually dropped.
pub fn sanitize_display_field_with_limit(value: &str, max_len: usize) -> String {
    let max_len = max_len.max(MIN_MAX_LEN);

    let mut out = String::with_capacity(value.len().min(max_len));
    for ch in value.chars() {
        if out.len() + escaped_len(ch) > max_len {
            out.push(TRUNCATION_MARK);
            break;
        }
        push_escaped(&mut out, ch);
    }
    out
}

/// Escape control characters without truncating.
pub(crate) fn push_display_escaped(out: &mut String, value: &str) {
    for ch in value.chars() {
        push_escaped(out, ch);
    }
}

fn escaped_len(ch: char) -> usize {
    match ch {
        '\n' | '\r' | '\t' => 2,
        c if c.is_control() => 1,
        c => c.len_utf8(),
    }
}

fn push_escaped(out: &mut String, ch: char) {
    match ch {
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        c if c.is_control() => out.push('?'),
        c => out.push(c),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/internal/support_display_sanitize_test.rs"]
mod support_display_sanitize_test;
