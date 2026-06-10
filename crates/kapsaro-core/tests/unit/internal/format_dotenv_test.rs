// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for dotenv format parsing and serialization

use crate::format::kv::dotenv::{
    build_dotenv_string, is_valid_key_name, parse_dotenv, parse_dotenv_value,
    validate_dotenv_strict,
};
use std::collections::HashMap;

#[test]
fn test_is_valid_key_name() {
    assert!(is_valid_key_name("KEY"));
    assert!(is_valid_key_name("_KEY"));
    assert!(is_valid_key_name("KEY_123"));
    assert!(is_valid_key_name("key"));
    assert!(!is_valid_key_name("123KEY"));
    assert!(!is_valid_key_name("KEY-VAL"));
    assert!(!is_valid_key_name("KEY.VAL"));
}

#[test]
fn test_parse_dotenv_value() {
    // Unquoted
    assert_eq!(parse_dotenv_value("value").as_str(), "value");

    // Single-quoted (no escaping)
    assert_eq!(parse_dotenv_value("'value'").as_str(), "value");
    assert_eq!(parse_dotenv_value("'val\\nue'").as_str(), "val\\nue");

    // Double-quoted (with escaping)
    assert_eq!(parse_dotenv_value("\"value\"").as_str(), "value");
    assert_eq!(parse_dotenv_value("\"val\\nue\"").as_str(), "val\nue");
    assert_eq!(parse_dotenv_value("\"val\\\"ue\"").as_str(), "val\"ue");
    assert_eq!(parse_dotenv_value("\"val\\\\nue\"").as_str(), "val\\nue"); // \\ -> \
}

#[test]
fn test_parse_dotenv() {
    let content = r#"
# Comment
KEY1=value1
KEY2="quoted value"
KEY3='single quoted'
export KEY4=exported
KEY5="line\\nbreak"

# Empty lines and invalid lines are ignored
INVALID-KEY=ignored
123INVALID=ignored
"#;

    let map = parse_dotenv(content).unwrap();

    assert_eq!(map.get("KEY1").map(|value| value.as_str()), Some("value1"));
    assert_eq!(
        map.get("KEY2").map(|value| value.as_str()),
        Some("quoted value")
    );
    assert_eq!(
        map.get("KEY3").map(|value| value.as_str()),
        Some("single quoted")
    );
    assert_eq!(
        map.get("KEY4").map(|value| value.as_str()),
        Some("exported")
    );
    assert_eq!(
        map.get("KEY5").map(|value| value.as_str()),
        Some("line\\nbreak")
    );
    assert_eq!(map.get("INVALID-KEY"), None);
    assert_eq!(map.get("123INVALID"), None);
}

#[test]
fn test_build_dotenv_string() {
    let mut map = HashMap::new();
    map.insert("KEY1".to_string(), "value1".to_string());
    map.insert("KEY2".to_string(), "value with spaces".to_string());
    map.insert("KEY3".to_string(), "value\nwith\nnewlines".to_string());
    map.insert("KEY4".to_string(), "value\"with\"quotes".to_string());
    map.insert("KEY5".to_string(), "simple".to_string());

    let output = build_dotenv_string(&map);

    // Should be sorted
    assert!(output.find("KEY1") < output.find("KEY2"));
    assert!(output.find("KEY2") < output.find("KEY3"));

    // Simple value should not be quoted
    assert!(output.contains("KEY5=simple\n"));

    // Values with special characters should be quoted
    assert!(output.contains("KEY2=\"value with spaces\"\n"));
    assert!(output.contains("KEY3=\"value\\nwith\\nnewlines\"\n"));
    assert!(output.contains("KEY4=\"value\\\"with\\\"quotes\"\n"));
}

#[test]
fn test_roundtrip() {
    let mut original = HashMap::new();
    original.insert("KEY1".to_string(), "simple".to_string());
    original.insert("KEY2".to_string(), "value with spaces".to_string());
    original.insert("KEY3".to_string(), "value\nwith\nnewlines".to_string());
    original.insert("KEY4".to_string(), "value\"with\"quotes".to_string());
    original.insert("KEY5".to_string(), "value\\with\\backslashes".to_string());

    let serialized = build_dotenv_string(&original);
    let parsed = parse_dotenv(&serialized).unwrap();

    for (key, value) in original {
        assert_eq!(
            parsed.get(&key).map(|value| value.as_str()),
            Some(value.as_str())
        );
    }
}

// ============================================================================
// validate_dotenv_strict tests
// ============================================================================

#[test]
fn test_validate_dotenv_strict_valid() {
    let content = "DB_URL=postgres://localhost\nAPI_KEY=secret\n";
    assert!(validate_dotenv_strict(content).is_ok());
}

#[test]
fn test_validate_dotenv_strict_with_comments_and_empty_lines() {
    let content = "# comment\n\nDB_URL=postgres://localhost\n";
    assert!(validate_dotenv_strict(content).is_ok());
}

#[test]
fn test_validate_dotenv_strict_with_export_prefix() {
    let content = "export DB_URL=postgres://localhost\n";
    assert!(validate_dotenv_strict(content).is_ok());
}

#[test]
fn test_validate_dotenv_strict_invalid_no_equals() {
    let content = "DB_URL=valid\nINVALID_LINE\n";
    assert!(validate_dotenv_strict(content).is_err());
}

#[test]
fn test_validate_dotenv_strict_invalid_key_name() {
    let content = "123BAD=value\n";
    assert!(validate_dotenv_strict(content).is_err());
}

#[test]
fn test_validate_dotenv_strict_empty_content() {
    let content = "";
    assert!(validate_dotenv_strict(content).is_err());
}

#[test]
fn test_validate_dotenv_strict_only_comments() {
    let content = "# just a comment\n# another\n";
    assert!(validate_dotenv_strict(content).is_err());
}
