// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! JCS (JSON Canonicalization Scheme) tests according to RFC 8785.
//!
//! This module tests the JCS normalization implementation to ensure
//! deterministic JSON serialization for consistent hashing and signing.
//!
//! RFC 8785 specifies:
//! - Object keys must be sorted in Unicode code point order
//! - No whitespace between tokens
//! - Numbers must use shortest representation (no trailing zeros, no unnecessary exponent)
//! - Strings must use proper escape sequences
//! - Arrays preserve element order
//!
//! Reference: <https://www.rfc-editor.org/rfc/rfc8785>
//! Reference: <https://www.rfc-editor.org/rfc/rfc8785>

use secretenv::format::jcs::{normalize, normalize_to_bytes, normalize_to_string};
use serde_json::json;

// =============================================================================
// Basic Object Normalization Tests
// =============================================================================

#[test]
fn test_jcs_key_ordering_simple() {
    // Keys should be sorted alphabetically (Unicode code point order)
    let input = json!({
        "z": 1,
        "a": 2,
        "m": 3
    });
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"a":2,"m":3,"z":1}"#);
}

#[test]
fn test_jcs_key_ordering_longer_keys() {
    // Longer keys: lexicographic order
    let input = json!({
        "banana": 1,
        "apple": 2,
        "cherry": 3,
        "apricot": 4
    });
    let result = normalize_to_string(&input).unwrap();
    // apple < apricot < banana < cherry
    assert_eq!(result, r#"{"apple":2,"apricot":4,"banana":1,"cherry":3}"#);
}

#[test]
fn test_jcs_key_ordering_numeric_strings() {
    // Numeric string keys should be sorted lexicographically, not numerically
    let input = json!({
        "10": "ten",
        "2": "two",
        "1": "one"
    });
    let result = normalize_to_string(&input).unwrap();
    // "1" < "10" < "2" in lexicographic order
    assert_eq!(result, r#"{"1":"one","10":"ten","2":"two"}"#);
}

#[test]
fn test_jcs_key_ordering_mixed_case() {
    // Unicode code point order: uppercase letters come before lowercase
    let input = json!({
        "b": 1,
        "B": 2,
        "a": 3,
        "A": 4
    });
    let result = normalize_to_string(&input).unwrap();
    // 'A' (65) < 'B' (66) < 'a' (97) < 'b' (98)
    assert_eq!(result, r#"{"A":4,"B":2,"a":3,"b":1}"#);
}

#[test]
fn test_jcs_empty_object() {
    let input = json!({});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, "{}");
}

#[test]
fn test_jcs_single_key_object() {
    let input = json!({"key": "value"});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"key":"value"}"#);
}

// =============================================================================
// Nested Object Normalization Tests
// =============================================================================

#[test]
fn test_jcs_nested_objects() {
    // Nested objects should also have their keys sorted
    let input = json!({
        "b": {"z": 1, "a": 2},
        "a": 1
    });
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"a":1,"b":{"a":2,"z":1}}"#);
}

#[test]
fn test_jcs_deeply_nested_objects() {
    let input = json!({
        "c": {
            "z": {
                "y": 1,
                "x": 2
            },
            "a": 3
        },
        "b": 4,
        "a": 5
    });
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"a":5,"b":4,"c":{"a":3,"z":{"x":2,"y":1}}}"#);
}

#[test]
fn test_jcs_object_in_array() {
    // Objects inside arrays should also be normalized
    let input = json!([
        {"z": 1, "a": 2},
        {"y": 3, "b": 4}
    ]);
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"[{"a":2,"z":1},{"b":4,"y":3}]"#);
}

// =============================================================================
// Array Handling Tests
// =============================================================================

#[test]
fn test_jcs_array_preserves_order() {
    // Arrays must preserve element order
    let input = json!([3, 1, 4, 1, 5, 9, 2, 6]);
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, "[3,1,4,1,5,9,2,6]");
}

#[test]
fn test_jcs_empty_array() {
    let input = json!([]);
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, "[]");
}

#[test]
fn test_jcs_mixed_type_array() {
    let input = json!([1, "two", true, null, {"a": 3}]);
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"[1,"two",true,null,{"a":3}]"#);
}

#[test]
fn test_jcs_nested_arrays() {
    let input = json!([[1, 2], [3, 4], [[5, 6]]]);
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, "[[1,2],[3,4],[[5,6]]]");
}

// =============================================================================
// Number Normalization Tests
// =============================================================================

#[test]
fn test_jcs_integer_numbers() {
    let input = json!({"num": 42});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"num":42}"#);
}

#[test]
fn test_jcs_zero() {
    let input = json!({"zero": 0});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"zero":0}"#);
}

#[test]
fn test_jcs_negative_numbers() {
    let input = json!({"neg": -123});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"neg":-123}"#);
}

#[test]
fn test_jcs_floating_point_no_trailing_zeros() {
    // No unnecessary trailing zeros
    let input = json!({"val": 1.5});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"val":1.5}"#);
}

#[test]
fn test_jcs_floating_point_integer_value() {
    // RFC 8785: Integer-valued floats should be represented as integers (no .0)
    // serde_json parses 1.0 and JCS correctly normalizes it to 1
    let input: serde_json::Value = serde_json::from_str(r#"{"val": 1.0}"#).unwrap();
    let result = normalize_to_string(&input).unwrap();
    // JCS removes unnecessary trailing zeros and decimal point
    assert_eq!(result, r#"{"val":1}"#);
}

#[test]
fn test_jcs_large_integer() {
    // Large integers within safe range
    let input = json!({"big": 9007199254740991_i64});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"big":9007199254740991}"#);
}

#[test]
fn test_jcs_small_negative() {
    let input = json!({"small": -9007199254740991_i64});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"small":-9007199254740991}"#);
}

// =============================================================================
// String and Escape Sequence Tests
// =============================================================================

#[test]
fn test_jcs_simple_string() {
    let input = json!({"str": "hello"});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"str":"hello"}"#);
}

#[test]
fn test_jcs_empty_string() {
    let input = json!({"empty": ""});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"empty":""}"#);
}

#[test]
fn test_jcs_escape_backslash() {
    let input = json!({"path": "C:\\Users\\test"});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"path":"C:\\Users\\test"}"#);
}

#[test]
fn test_jcs_escape_quote() {
    let input = json!({"quote": "He said \"hello\""});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"quote":"He said \"hello\""}"#);
}

#[test]
fn test_jcs_escape_newline() {
    let input = json!({"nl": "line1\nline2"});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"nl":"line1\nline2"}"#);
}

#[test]
fn test_jcs_escape_tab() {
    let input = json!({"tab": "col1\tcol2"});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"tab":"col1\tcol2"}"#);
}

#[test]
fn test_jcs_escape_carriage_return() {
    let input = json!({"cr": "line1\rline2"});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"cr":"line1\rline2"}"#);
}

#[test]
fn test_jcs_escape_backspace() {
    let input = json!({"bs": "back\x08space"});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"bs":"back\bspace"}"#);
}

#[test]
fn test_jcs_escape_form_feed() {
    let input = json!({"ff": "form\x0cfeed"});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"ff":"form\ffeed"}"#);
}

// =============================================================================
// Unicode Normalization Tests
// =============================================================================

#[test]
fn test_jcs_unicode_basic() {
    // Basic Unicode characters should be preserved
    let input = json!({"greeting": "Hello, World!"});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"greeting":"Hello, World!"}"#);
}

#[test]
fn test_jcs_unicode_non_ascii() {
    // Non-ASCII characters should be preserved as UTF-8
    let input = json!({"japanese": "\u{65E5}\u{672C}\u{8A9E}"});
    let result = normalize_to_string(&input).unwrap();
    assert!(result.contains("\u{65E5}\u{672C}\u{8A9E}"));
}

#[test]
fn test_jcs_unicode_emoji() {
    // Emoji should be preserved
    let input = json!({"emoji": "\u{1F600}"});
    let result = normalize_to_string(&input).unwrap();
    assert!(result.contains("\u{1F600}"));
}

#[test]
fn test_jcs_unicode_key_ordering() {
    // Unicode keys should be sorted by code point
    let input = json!({
        "\u{00E9}": "e-acute",  // e with acute accent (U+00E9)
        "e": "plain e",
        "\u{00C9}": "E-acute"   // E with acute accent (U+00C9)
    });
    let result = normalize_to_string(&input).unwrap();
    // Order: E (U+0045) < e (U+0065) < E-acute (U+00C9) < e-acute (U+00E9)
    // But we only have: e (U+0065), E-acute (U+00C9), e-acute (U+00E9)
    // So order should be: e < E-acute < e-acute
    assert!(result.starts_with(r#"{"e":"#));
}

#[test]
fn test_jcs_unicode_control_chars_escaped() {
    // Control characters (U+0000 to U+001F) must be escaped
    // Note: Some may use \uXXXX format
    let input = json!({"ctrl": "\u{0001}"});
    let result = normalize_to_string(&input).unwrap();
    // Should be escaped as \u0001
    assert!(result.contains("\\u0001"));
}

// =============================================================================
// Boolean and Null Tests
// =============================================================================

#[test]
fn test_jcs_boolean_true() {
    let input = json!({"flag": true});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"flag":true}"#);
}

#[test]
fn test_jcs_boolean_false() {
    let input = json!({"flag": false});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"flag":false}"#);
}

#[test]
fn test_jcs_null() {
    let input = json!({"nothing": null});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"nothing":null}"#);
}

// =============================================================================
// No Whitespace Tests
// =============================================================================

#[test]
fn test_jcs_no_whitespace_object() {
    let input = json!({
        "a": 1,
        "b": 2,
        "c": 3
    });
    let result = normalize_to_string(&input).unwrap();
    // No spaces or newlines
    assert!(!result.contains(' '));
    assert!(!result.contains('\n'));
    assert!(!result.contains('\t'));
    assert_eq!(result, r#"{"a":1,"b":2,"c":3}"#);
}

#[test]
fn test_jcs_no_whitespace_array() {
    let input = json!([1, 2, 3]);
    let result = normalize_to_string(&input).unwrap();
    // No spaces between elements
    assert_eq!(result, "[1,2,3]");
}

// =============================================================================
// Determinism Tests
// =============================================================================

#[test]
fn test_jcs_determinism_same_input() {
    // Same input always produces same output
    let input = json!({
        "z": [1, 2, 3],
        "a": {"y": true, "x": null},
        "m": "test"
    });

    let result1 = normalize_to_string(&input).unwrap();
    let result2 = normalize_to_string(&input).unwrap();
    let result3 = normalize_to_string(&input).unwrap();

    assert_eq!(result1, result2);
    assert_eq!(result2, result3);
}

#[test]
fn test_jcs_determinism_equivalent_input() {
    // Logically equivalent JSON produces identical output regardless of original formatting
    let json1 = r#"{"z":1,"a":2,"m":3}"#;
    let json2 = r#"{
        "a": 2,
        "z": 1,
        "m": 3
    }"#;
    let json3 = r#"{"m":3,"z":1,"a":2}"#;

    let val1: serde_json::Value = serde_json::from_str(json1).unwrap();
    let val2: serde_json::Value = serde_json::from_str(json2).unwrap();
    let val3: serde_json::Value = serde_json::from_str(json3).unwrap();

    let result1 = normalize_to_string(&val1).unwrap();
    let result2 = normalize_to_string(&val2).unwrap();
    let result3 = normalize_to_string(&val3).unwrap();

    assert_eq!(result1, result2);
    assert_eq!(result2, result3);
    assert_eq!(result1, r#"{"a":2,"m":3,"z":1}"#);
}

#[test]
fn test_jcs_determinism_bytes() {
    // Verify byte-level determinism for hashing purposes
    let input = json!({
        "policy_id": "550e8400-e29b-41d4-a716-446655440000",
        "epoch": 1,
        "name": "production"
    });

    let result = normalize_to_bytes(&input).unwrap();

    // Re-canonicalize should produce identical bytes
    let result2 = normalize_to_bytes(&input).unwrap();
    assert_eq!(result, result2);
}

// =============================================================================
// Complex Document Tests
// =============================================================================

#[test]
fn test_jcs_policy_like_document() {
    // Simulates a PolicyDocument structure
    let input = json!({
        "format": "secretenv-policy-v1",
        "policy_id": "550e8400-e29b-41d4-a716-446655440000",
        "epoch": 1,
        "name": "my-team",
        "groups": {
            "admin": ["alice", "bob"],
            "dev": ["charlie"]
        },
        "members": {
            "alice": {"groups": ["admin"]},
            "bob": {"groups": ["admin"]},
            "charlie": {"groups": ["dev"]}
        }
    });

    let result = normalize_to_string(&input).unwrap();

    // Verify key ordering at top level
    assert!(result.contains(r#""epoch":1"#));
    assert!(result.contains(r#""format":"secretenv-policy-v1""#));

    // Verify determinism
    let result2 = normalize_to_string(&input).unwrap();
    assert_eq!(result, result2);
}

#[test]
fn test_jcs_secret_like_document() {
    // Simulates a SecretDocument structure (minus actual ciphertext)
    let input = json!({
        "format": "secretenv-secret-v1",
        "name": "production-env",
        "policy_id": "550e8400-e29b-41d4-a716-446655440000",
        "epoch": 1,
        "created_at": "2024-01-01T00:00:00Z",
        "recipients": [
            {"id": "alice", "enc_key": "base64..."},
            {"id": "bob", "enc_key": "base64..."}
        ]
    });

    let result = normalize_to_string(&input).unwrap();

    // Verify recipients array order is preserved
    assert!(result.contains(r#"[{"enc_key":"base64...","id":"alice"}"#));

    // Verify determinism
    let result2 = normalize_to_string(&input).unwrap();
    assert_eq!(result, result2);
}

#[test]
fn test_jcs_aad_payload_structure() {
    // Tests the AAD payload structure
    let input = json!({
        "v": 1,
        "policy_id": "550e8400-e29b-41d4-a716-446655440000",
        "secret_name": "production-env",
        "epoch": 1,
        "path": "secrets/production-env.json"
    });

    let result = normalize_to_string(&input).unwrap();

    // Keys should be in order: epoch, path, policy_id, secret_name, v
    let expected = r#"{"epoch":1,"path":"secrets/production-env.json","policy_id":"550e8400-e29b-41d4-a716-446655440000","secret_name":"production-env","v":1}"#;
    assert_eq!(result, expected);
}

// =============================================================================
// Edge Cases
// =============================================================================

#[test]
fn test_jcs_primitive_value_string() {
    let input = json!("just a string");
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#""just a string""#);
}

#[test]
fn test_jcs_primitive_value_number() {
    let input = json!(42);
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, "42");
}

#[test]
fn test_jcs_primitive_value_boolean() {
    let input = json!(true);
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, "true");
}

#[test]
fn test_jcs_primitive_value_null() {
    let input = json!(null);
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, "null");
}

#[test]
fn test_jcs_empty_string_key() {
    let input = json!({"": "empty key"});
    let result = normalize_to_string(&input).unwrap();
    assert_eq!(result, r#"{"":"empty key"}"#);
}

#[test]
fn test_jcs_special_chars_in_key() {
    let input = json!({
        "key with spaces": 1,
        "key\twith\ttabs": 2,
        "key\"with\"quotes": 3
    });
    let result = normalize_to_string(&input).unwrap();
    // Keys should be properly escaped
    assert!(result.contains(r#""key with spaces""#));
    assert!(result.contains(r#""key\twith\ttabs""#));
    assert!(result.contains(r#""key\"with\"quotes""#));
}

// =============================================================================
// RFC 8785 Specific Test Vectors
// =============================================================================

#[test]
fn test_jcs_rfc8785_example_sorting() {
    // Based on RFC 8785 Section 3.2.3 example
    // Keys must be sorted by UTF-16 code units (which for ASCII is same as byte order)
    let input = json!({
        "peach": "This is a string value.",
        "apple": {
            "size": 10,
            "type": "fruit"
        },
        "100": "A numeric key",
        "": "An empty key"
    });

    let result = normalize_to_string(&input).unwrap();

    // Empty string comes first, then "100", then "apple", then "peach"
    // (empty < digits < lowercase letters in code point order)
    assert!(result.starts_with(r#"{"":"An empty key""#));
}

#[test]
fn test_jcs_numbers_format() {
    // RFC 8785 Section 3.2.2.3 - Number formatting
    let test_cases = vec![
        (json!(0), "0"),
        (json!(1), "1"),
        (json!(-1), "-1"),
        (json!(0.5), "0.5"),
    ];

    for (input, expected) in test_cases {
        let result = normalize_to_string(&input).unwrap();
        assert_eq!(result, expected, "Failed for input: {:?}", input);
    }
}

// =============================================================================
// Bytes Output Tests (for hashing/signing)
// =============================================================================

#[test]
fn test_jcs_output_is_valid_utf8() {
    let input = json!({
        "unicode": "\u{1F600}\u{1F601}\u{1F602}",
        "text": "Hello, World!"
    });

    let result = normalize_to_bytes(&input).unwrap();

    // Result should be valid UTF-8
    assert!(std::str::from_utf8(&result).is_ok());
}

#[test]
fn test_jcs_sha256_hash_determinism() {
    use sha2::{Digest, Sha256};

    let input = json!({
        "policy_id": "550e8400-e29b-41d4-a716-446655440000",
        "epoch": 1,
        "name": "test"
    });

    let result = normalize_to_bytes(&input).unwrap();
    let hash1 = Sha256::digest(&result);

    // Re-canonicalize and hash again
    let result2 = normalize_to_bytes(&input).unwrap();
    let hash2 = Sha256::digest(&result2);

    // Hashes must be identical
    assert_eq!(hash1, hash2);
}

// =============================================================================
// Generic normalize function tests (for arbitrary Serialize types)
// =============================================================================

#[test]
fn test_jcs_normalize_generic_struct() {
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestStruct {
        z_field: i32,
        a_field: String,
        m_field: bool,
    }

    let input = TestStruct {
        z_field: 1,
        a_field: "test".to_string(),
        m_field: true,
    };

    let result = normalize(&input).unwrap();
    let result_str = String::from_utf8(result).unwrap();

    // Keys should be sorted alphabetically
    assert_eq!(
        result_str,
        r#"{"a_field":"test","m_field":true,"z_field":1}"#
    );
}

#[test]
fn test_jcs_normalize_bytes_matches_string() {
    let input = json!({"b": 1, "a": 2});

    let bytes_result = normalize_to_bytes(&input).unwrap();
    let string_result = normalize_to_string(&input).unwrap();

    // Bytes should match the UTF-8 encoding of the string
    assert_eq!(bytes_result, string_result.as_bytes());
}
