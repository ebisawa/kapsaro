// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::support::display::{
    format_path_for_message, sanitize_display_field, sanitize_display_field_with_limit,
};
use kapsaro_core::cli_api::presentation::kid::format_kid_display_lossy;

#[test]
fn test_sanitize_display_field_escapes_newlines_and_controls() {
    let input = "alice@example.com\nbob\r\t\x07";
    let out = sanitize_display_field(input);
    assert!(!out.contains('\n'));
    assert!(!out.contains('\r'));
    assert!(out.contains("\\n"));
    assert!(out.contains("\\r"));
    assert!(out.contains("\\t"));
}

/// The limit bounds what a reader is shown, and the truncation mark is part of
/// that, so the mark has to fit inside the limit rather than beyond it.
#[test]
fn test_sanitize_display_field_truncates_within_the_limit() {
    let input = "a".repeat(300);

    let out = sanitize_display_field_with_limit(&input, 50);

    assert_eq!(out.len(), 50);
    assert!(out.contains('…'));
}

/// An escaped character is two bytes and the mark is three, so a limit reached
/// midway through one still leaves an output no longer than it was given.
#[test]
fn test_sanitize_display_field_stays_within_the_limit_around_an_escape() {
    let input = format!("{}\n{}", "a".repeat(7), "a".repeat(20));

    let out = sanitize_display_field_with_limit(&input, 8);

    assert!(out.len() <= 8, "{out}");
    assert!(out.ends_with('…'), "{out}");
}

/// Truncation must land on a character boundary, not a byte offset.
#[test]
fn test_sanitize_display_field_keeps_multibyte_characters_intact() {
    let input = format!("{}{}", "A".repeat(59), '\u{3042}');

    let out = sanitize_display_field_with_limit(&input, 60);

    assert_eq!(out, format!("{}\u{2026}", "A".repeat(57)));
}

#[test]
fn test_sanitize_display_field_omits_the_mark_when_the_input_fits() {
    let input = "A".repeat(60);

    let out = sanitize_display_field_with_limit(&input, 60);

    assert_eq!(out, input);
}

/// A bidirectional override reorders what follows it, so a name carrying one
/// can be displayed as a different name entirely. It sits outside the control
/// block, which is why the escaping names it directly.
#[test]
fn test_sanitize_display_field_escapes_bidirectional_overrides() {
    let input = "alice\u{202E}bob\u{202C}";

    let out = sanitize_display_field(input);

    assert_eq!(out, "alice?bob?");
}

/// A zero-width or other format character renders as nothing, so it can hide
/// the difference between two names that must not be confused.
#[test]
fn test_sanitize_display_field_escapes_invisible_characters() {
    let input = "ali\u{200B}ce\u{FEFF}\u{2066}x\u{2069}";

    let out = sanitize_display_field(input);

    assert_eq!(out, "ali?ce??x?");
}

/// A line or paragraph separator ends the line wherever it is rendered, and one
/// inside a JSON string ends the literal for a JavaScript parser reading the
/// diagnostic. Neither sits in the control block, so the escaping names them.
#[test]
fn test_sanitize_display_field_escapes_line_and_paragraph_separators() {
    let input = "alice\u{2028}bob\u{2029}carol";

    let out = sanitize_display_field(input);

    assert_eq!(out, "alice?bob?carol");
}

/// Ordinary text outside ASCII stays as it is: the escaping is aimed at what
/// reorders or hides, not at every character a member handle may hold.
#[test]
fn test_sanitize_display_field_keeps_printable_non_ascii_text() {
    let input = "田中\u{00E9}";

    let out = sanitize_display_field(input);

    assert_eq!(out, input);
}

#[test]
fn test_format_path_for_message_spells_out_a_newline_in_a_name() {
    let rendered = format_path_for_message("/tmp/first\nWarning: forged");

    assert_eq!(rendered, "/tmp/first\\nWarning: forged");
}

#[test]
fn test_format_kid_display_lossy_sanitizes_invalid_kid() {
    let kid = "BADKID\nINJECT";
    let out = format_kid_display_lossy(kid);
    assert!(!out.contains('\n'));
    assert!(out.contains("\\n"));
}
