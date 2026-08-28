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
/// `max_len` bounds the escaped output in bytes, the truncation mark included:
/// the mark is what a reader is shown, so a bound that excluded it would not be
/// the bound the caller asked for. The mark is appended only when input
/// characters were actually dropped, and the text before it is cut back far
/// enough to leave room for it.
pub fn sanitize_display_field_with_limit(value: &str, max_len: usize) -> String {
    let max_len = max_len.max(MIN_MAX_LEN);

    let mut out = String::with_capacity(value.len().min(max_len));
    let mut mark_fits_at = 0;
    for ch in value.chars() {
        if out.len() + escaped_len(ch) > max_len {
            out.truncate(mark_fits_at);
            out.push(TRUNCATION_MARK);
            return out;
        }
        push_escaped(&mut out, ch);
        if out.len() + TRUNCATION_MARK.len_utf8() <= max_len {
            mark_fits_at = out.len();
        }
    }
    out
}

/// Escape control characters without truncating.
pub(crate) fn push_display_escaped(out: &mut String, value: &str) {
    for ch in value.chars() {
        push_escaped(out, ch);
    }
}

/// A path rendered inside prose, with control characters spelled out.
///
/// An entry name is chosen by whoever can write the directory. A newline in one
/// would otherwise let it forge a second warning line on standard error.
pub(crate) fn format_path_for_message(display: &str) -> String {
    let mut out = String::with_capacity(display.len());
    push_display_escaped(&mut out, display);
    out
}

fn escaped_len(ch: char) -> usize {
    match ch {
        '\n' | '\r' | '\t' => 2,
        c if needs_placeholder(c) => 1,
        c => c.len_utf8(),
    }
}

fn push_escaped(out: &mut String, ch: char) {
    match ch {
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        c if needs_placeholder(c) => out.push('?'),
        c => out.push(c),
    }
}

/// Whether a character stands for itself once it reaches a terminal.
pub(crate) fn needs_placeholder(ch: char) -> bool {
    ch.is_control() || reorders_or_hides_text(ch)
}

/// Characters that reorder the text around them, render as nothing, or break
/// the line they sit on.
///
/// A bidirectional override or isolate makes what follows appear in a different
/// order than it is stored, and a zero-width or other format character occupies
/// no space at all. Entry names, member handles and kids are chosen by whoever
/// wrote the document being displayed, so either kind lets one name be shown as
/// another — `alice` and `bob` can be arranged to read as one identifier while
/// naming the other. The line and paragraph separators are the third case: they
/// end a line wherever a reader renders them, and one inside a JSON string ends
/// the literal as far as a JavaScript parser is concerned. `char::is_control`
/// covers only the Cc block and passes all of these through, so they are named
/// here.
fn reorders_or_hides_text(ch: char) -> bool {
    matches!(
        ch,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{2029}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

#[cfg(test)]
#[path = "../../tests/unit/internal/support_display_sanitize_test.rs"]
mod support_display_sanitize_test;
