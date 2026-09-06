// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for deterministic JSON canonicalization, escaped strings, and numeric formatting.
//! Preserves named input cases and exact byte expectations for signing and hashing.

use crate::format::jcs::{normalize, normalize_to_bytes, normalize_to_string};
use serde_json::json;

fn assert_normalization_cases(cases: &[(&str, serde_json::Value, &str)]) {
    for (name, input, expected) in cases {
        let actual = normalize_to_string(input).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(actual, *expected, "{name}");
    }
}

#[test]
fn test_jcs_object_and_array_cases() {
    assert_normalization_cases(&[
        (
            "simple keys",
            json!({"z":1,"a":2,"m":3}),
            r#"{"a":2,"m":3,"z":1}"#,
        ),
        (
            "longer keys",
            json!({"banana":1,"apple":2,"cherry":3,"apricot":4}),
            r#"{"apple":2,"apricot":4,"banana":1,"cherry":3}"#,
        ),
        (
            "numeric keys",
            json!({"10":"ten","2":"two","1":"one"}),
            r#"{"1":"one","10":"ten","2":"two"}"#,
        ),
        (
            "mixed case keys",
            json!({"b":1,"B":2,"a":3,"A":4}),
            r#"{"A":4,"B":2,"a":3,"b":1}"#,
        ),
        ("empty object", json!({}), "{}"),
        ("single key", json!({"key":"value"}), r#"{"key":"value"}"#),
        (
            "nested objects",
            json!({"b":{"z":1,"a":2},"a":1}),
            r#"{"a":1,"b":{"a":2,"z":1}}"#,
        ),
        (
            "deeply nested objects",
            json!({"c":{"z":{"y":1,"x":2},"a":3},"b":4,"a":5}),
            r#"{"a":5,"b":4,"c":{"a":3,"z":{"x":2,"y":1}}}"#,
        ),
        (
            "objects in array",
            json!([{"z":1,"a":2},{"y":3,"b":4}]),
            r#"[{"a":2,"z":1},{"b":4,"y":3}]"#,
        ),
        (
            "array order",
            json!([3, 1, 4, 1, 5, 9, 2, 6]),
            "[3,1,4,1,5,9,2,6]",
        ),
        ("empty array", json!([]), "[]"),
        (
            "mixed array",
            json!([1,"two",true,null,{"a":3}]),
            r#"[1,"two",true,null,{"a":3}]"#,
        ),
        (
            "nested arrays",
            json!([[1, 2], [3, 4], [[5, 6]]]),
            "[[1,2],[3,4],[[5,6]]]",
        ),
        (
            "object whitespace",
            json!({"a":1,"b":2,"c":3}),
            r#"{"a":1,"b":2,"c":3}"#,
        ),
        ("array whitespace", json!([1, 2, 3]), "[1,2,3]"),
        ("empty key", json!({"":"empty key"}), r#"{"":"empty key"}"#),
    ]);
}

#[test]
fn test_jcs_number_and_primitive_cases() {
    assert_normalization_cases(&[
        ("integer", json!({"num":42}), r#"{"num":42}"#),
        ("zero", json!({"zero":0}), r#"{"zero":0}"#),
        ("negative", json!({"neg":-123}), r#"{"neg":-123}"#),
        (
            "largest safe integer",
            json!({"big":9007199254740991_i64}),
            r#"{"big":9007199254740991}"#,
        ),
        (
            "smallest safe integer",
            json!({"small":-9007199254740991_i64}),
            r#"{"small":-9007199254740991}"#,
        ),
        ("true field", json!({"flag":true}), r#"{"flag":true}"#),
        ("false field", json!({"flag":false}), r#"{"flag":false}"#),
        ("null field", json!({"nothing":null}), r#"{"nothing":null}"#),
        (
            "string primitive",
            json!("just a string"),
            r#""just a string""#,
        ),
        ("number primitive", json!(42), "42"),
        ("boolean primitive", json!(true), "true"),
        ("null primitive", json!(null), "null"),
    ]);
}

#[test]
fn test_jcs_string_and_unicode_cases() {
    assert_normalization_cases(&[
        ("simple", json!({"str":"hello"}), r#"{"str":"hello"}"#),
        ("empty", json!({"empty":""}), r#"{"empty":""}"#),
        (
            "backslash",
            json!({"path":"C:\\Users\\test"}),
            r#"{"path":"C:\\Users\\test"}"#,
        ),
        (
            "quote",
            json!({"quote":"He said \"hello\""}),
            r#"{"quote":"He said \"hello\""}"#,
        ),
        (
            "newline",
            json!({"nl":"line1\nline2"}),
            r#"{"nl":"line1\nline2"}"#,
        ),
        (
            "tab",
            json!({"tab":"col1\tcol2"}),
            r#"{"tab":"col1\tcol2"}"#,
        ),
        (
            "carriage return",
            json!({"cr":"line1\rline2"}),
            r#"{"cr":"line1\rline2"}"#,
        ),
        (
            "backspace",
            json!({"bs":"back\u{0008}space"}),
            r#"{"bs":"back\bspace"}"#,
        ),
        (
            "form feed",
            json!({"ff":"form\u{000c}feed"}),
            r#"{"ff":"form\ffeed"}"#,
        ),
        (
            "basic unicode",
            json!({"greeting":"Hello, World!"}),
            r#"{"greeting":"Hello, World!"}"#,
        ),
        (
            "non ascii",
            json!({"japanese":"日本語"}),
            r#"{"japanese":"日本語"}"#,
        ),
        ("emoji", json!({"emoji":"😀"}), r#"{"emoji":"😀"}"#),
        (
            "unicode keys",
            json!({"é":"e-acute","e":"plain e","É":"E-acute"}),
            r#"{"e":"plain e","É":"E-acute","é":"e-acute"}"#,
        ),
        (
            "control character",
            json!({"ctrl":"\u{0001}"}),
            r#"{"ctrl":"\u0001"}"#,
        ),
        (
            "escaped keys",
            json!({"key with spaces":1,"key\twith\ttabs":2,"key\"with\"quotes":3}),
            r#"{"key\twith\ttabs":2,"key with spaces":1,"key\"with\"quotes":3}"#,
        ),
    ]);
}

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

#[test]
fn test_jcs_policy_like_document() {
    // Simulates a PolicyDocument structure
    let input = json!({
        "format": "kapsaro-policy-v1",
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
    assert!(result.contains(r#""format":"kapsaro-policy-v1""#));

    // Verify determinism
    let result2 = normalize_to_string(&input).unwrap();
    assert_eq!(result, result2);
}

#[test]
fn test_jcs_secret_like_document() {
    // Simulates a SecretDocument structure (minus actual ciphertext)
    let input = json!({
        "format": "kapsaro-secret-v1",
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

    // The whole output is the signed byte string, so pinning only its prefix
    // would leave the rest free to change without failing.
    assert_eq!(
        result,
        concat!(
            r#"{"":"An empty key","100":"A numeric key","#,
            r#""apple":{"size":10,"type":"fruit"},"#,
            r#""peach":"This is a string value."}"#,
        ),
    );
}

#[test]
fn test_jcs_numbers_format() {
    // Accepted integer values retain their exact canonical representation.
    let test_cases = vec![
        (json!(0), "0"),
        (json!(1), "1"),
        (json!(-1), "-1"),
        // The largest integers that survive a round trip through f64.
        (json!(9007199254740991i64), "9007199254740991"),
        (json!(-9007199254740991i64), "-9007199254740991"),
    ];

    for (input, expected) in test_cases {
        let result = normalize_to_string(&input).unwrap();
        assert_eq!(result, expected, "Failed for input: {:?}", input);
    }
}

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

#[test]
fn test_jcs_number_contract_at_all_entry_points() {
    for number in [
        "9007199254740992",
        "9007199254740993",
        "-9007199254740992",
        "18446744073709551615",
        "1.5",
        "1.0",
        "1e0",
        "-0.0",
    ] {
        let value: serde_json::Value =
            serde_json::from_str(&format!(r#"{{"nested":[{{"number":{number}}}]}}"#)).unwrap();
        assert_eq!(
            normalize(&value).unwrap_err().kind(),
            crate::ErrorKind::Parse
        );
        assert_eq!(
            normalize_to_bytes(&value).unwrap_err().kind(),
            crate::ErrorKind::Parse
        );
        assert_eq!(
            normalize_to_string(&value).unwrap_err().kind(),
            crate::ErrorKind::Parse
        );
    }
}

#[test]
fn test_jcs_typed_number_contract() {
    for number in [
        9007199254740992_i128,
        -9007199254740992,
        i128::MAX,
        i128::MIN,
    ] {
        assert_eq!(
            normalize(&Some(vec![number])).unwrap_err().kind(),
            crate::ErrorKind::Parse
        );
    }
    assert_eq!(
        normalize(&u128::MAX).unwrap_err().kind(),
        crate::ErrorKind::Parse
    );
    for number in [0.0, 1.5, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(
            normalize(&Some(vec![number])).unwrap_err().kind(),
            crate::ErrorKind::Parse
        );
        assert_eq!(
            crate::format::token::TokenCodec::encode(
                crate::format::token::TokenCodec::JsonJcs,
                &Some(vec![number])
            )
            .unwrap_err()
            .kind(),
            crate::ErrorKind::Parse
        );
    }
    assert!(normalize(&f32::NAN).is_err());
    assert_eq!(
        normalize(&9007199254740991_u64).unwrap(),
        b"9007199254740991"
    );
    assert_eq!(
        normalize(&-9007199254740991_i64).unwrap(),
        b"-9007199254740991"
    );
}

#[test]
fn test_jcs_serializes_input_once() {
    struct Counted(std::cell::Cell<usize>);
    impl serde::Serialize for Counted {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.0.set(self.0.get() + 1);
            serializer.serialize_u64(42)
        }
    }
    let value = Counted(std::cell::Cell::new(0));
    assert_eq!(normalize(&value).unwrap(), b"42");
    assert_eq!(value.0.get(), 1);
    value.0.set(0);
    assert_eq!(
        crate::format::token::TokenCodec::encode(crate::format::token::TokenCodec::JsonJcs, &value)
            .unwrap(),
        "NDI"
    );
    assert_eq!(value.0.get(), 1);
}

#[test]
fn test_jcs_numeric_map_keys_are_strings() {
    let input = std::collections::BTreeMap::from([(u64::MAX, 42)]);
    assert_eq!(
        normalize(&input).unwrap(),
        br#"{"18446744073709551615":42}"#
    );
}

#[test]
fn test_jcs_numeric_map_key_encoding_matches_json_strings() {
    struct Entry<T>(T);
    impl<T: serde::Serialize> serde::Serialize for Entry<T> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeMap;
            let mut map = serializer.serialize_map(Some(1))?;
            map.serialize_entry(&self.0, &42)?;
            map.end()
        }
    }
    fn assert_key<T: serde::Serialize>(key: T) {
        let input = Entry(key);
        let expected = normalize(&serde_json::to_value(&input).unwrap()).unwrap();
        assert_eq!(normalize(&input).unwrap(), expected);
        assert_eq!(
            crate::format::token::TokenCodec::encode(
                crate::format::token::TokenCodec::JsonJcs,
                &input
            )
            .unwrap(),
            crate::format::codec::base64_public::encode_base64url_nopad(&expected)
        );
    }
    #[derive(serde::Serialize)]
    struct Key<T>(T);
    assert_key(u128::MAX);
    assert_key(i128::MIN);
    assert_key(Key(u64::MAX));
    assert_key(Key(1.0_f64));
    for key in [1.0, -0.0, 1e21, 1e-7, 1.5] {
        assert_key(key);
        assert_key(key as f32);
    }
    for key in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(
            normalize(&Entry(key)).unwrap_err().kind(),
            crate::ErrorKind::Parse
        );
    }
}

#[test]
fn test_jcs_wide_integers_preserve_safe_values() {
    assert_eq!(
        normalize(&9007199254740991u128).unwrap(),
        b"9007199254740991"
    );
    assert_eq!(
        normalize(&-9007199254740991i128).unwrap(),
        b"-9007199254740991"
    );
    let input = std::collections::BTreeMap::from([("number", 9007199254740992u128)]);
    assert_eq!(
        normalize(&input).unwrap_err().kind(),
        crate::ErrorKind::Parse
    );
}

#[test]
fn test_jcs_compound_number_contract() {
    #[derive(serde::Serialize)]
    enum Nested {
        Newtype(u64),
        Tuple(bool, u64),
        Struct { number: u64 },
    }
    #[derive(serde::Serialize)]
    struct TupleStruct(bool, u64);
    #[derive(serde::Serialize)]
    struct Newtype(u64);
    let invalid = 9007199254740993_u64;
    for value in [
        Nested::Newtype(invalid),
        Nested::Tuple(true, invalid),
        Nested::Struct { number: invalid },
    ] {
        assert_eq!(
            normalize(&value).unwrap_err().kind(),
            crate::ErrorKind::Parse
        );
    }
    assert!(normalize(&TupleStruct(true, invalid)).is_err());
    assert!(normalize(&Newtype(invalid)).is_err());
    assert!(normalize(&(true, invalid)).is_err());
    assert_eq!(
        normalize(&Nested::Tuple(true, 42)).unwrap(),
        br#"{"Tuple":[true,42]}"#
    );
}
