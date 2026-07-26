// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::support::display::{sanitize_display_field, sanitize_display_field_with_limit};
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

#[test]
fn test_sanitize_display_field_truncates() {
    let input = "a".repeat(300);
    let out = sanitize_display_field_with_limit(&input, 50);
    assert!(out.len() <= 60);
    assert!(out.contains('…'));
}

/// Truncation must land on a character boundary, not a byte offset.
#[test]
fn test_sanitize_display_field_keeps_multibyte_characters_intact() {
    let input = format!("{}{}", "A".repeat(59), '\u{3042}');

    let out = sanitize_display_field_with_limit(&input, 60);

    assert_eq!(out, format!("{}\u{2026}", "A".repeat(59)));
}

#[test]
fn test_sanitize_display_field_omits_the_mark_when_the_input_fits() {
    let input = "A".repeat(60);

    let out = sanitize_display_field_with_limit(&input, 60);

    assert_eq!(out, input);
}

#[test]
fn test_format_kid_display_lossy_sanitizes_invalid_kid() {
    let kid = "BADKID\nINJECT";
    let out = format_kid_display_lossy(kid);
    assert!(!out.contains('\n'));
    assert!(out.contains("\\n"));
}
