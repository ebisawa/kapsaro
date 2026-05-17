// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv_core::cli_api::test_support::helpers::display::{
    sanitize_display_field, sanitize_display_field_with_limit,
};
use secretenv_core::cli_api::test_support::helpers::kid::format_kid_display_lossy;

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

#[test]
fn test_format_kid_display_lossy_sanitizes_invalid_kid() {
    let kid = "BADKID\nINJECT";
    let out = format_kid_display_lossy(kid);
    assert!(!out.contains('\n'));
    assert!(out.contains("\\n"));
}
