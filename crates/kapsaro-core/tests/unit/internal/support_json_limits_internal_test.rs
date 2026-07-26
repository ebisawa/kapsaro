// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn accepts_simple_json() {
    let input = br#"{"key": "value", "num": 42}"#;
    assert!(validate_json_limits(input).is_ok());
}

#[test]
fn accepts_nested_json_within_limit() {
    let open: String = "{\"a\":".repeat(32) + "1";
    let close: String = "}".repeat(32);
    let json = format!("{}{}", open, close);
    assert!(validate_json_limits(json.as_bytes()).is_ok());
}

#[test]
fn rejects_excessive_depth() {
    let open: String = "{\"a\":".repeat(33) + "1";
    let close: String = "}".repeat(33);
    let json = format!("{}{}", open, close);
    let err = validate_json_limits(json.as_bytes()).unwrap_err();
    assert!(err.to_string().contains("nesting depth exceeds limit"));
}

#[test]
fn ignores_braces_in_strings() {
    let input = br#"{"data": "{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{"}"#;
    assert!(validate_json_limits(input).is_ok());
}

#[test]
fn handles_escaped_quotes_in_strings() {
    let input = br#"{"data": "value with \" escaped {{{ quote"}"#;
    assert!(validate_json_limits(input).is_ok());
}

/// Each member contributes a colon and a separating comma, so member counts are
/// derived from the budget rather than hardcoded.
fn json_object_with_members(count: usize) -> String {
    let entries: Vec<String> = (0..count).map(|i| format!("\"k{}\":\"v\"", i)).collect();
    format!("{{{}}}", entries.join(","))
}

#[test]
fn rejects_excessive_elements() {
    let json = json_object_with_members(MAX_JSON_ELEMENTS);

    let err = validate_json_limits(json.as_bytes()).unwrap_err();

    assert!(err.to_string().contains("element count exceeds limit"));
}

#[test]
fn accepts_element_count_within_limit() {
    let json = json_object_with_members(MAX_JSON_ELEMENTS / 4);

    assert!(validate_json_limits(json.as_bytes()).is_ok());
}

#[test]
fn accepts_array_within_limit() {
    let elements: Vec<&str> = (0..100).map(|_| "1").collect();
    let json = format!("[{}]", elements.join(","));
    assert!(validate_json_limits(json.as_bytes()).is_ok());
}
