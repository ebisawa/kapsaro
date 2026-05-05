// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::entry::KvEntryValue;

#[test]
fn kv_entry_value_disclosed_true_serializes() {
    let entry = KvEntryValue {
        salt: "test_salt".to_string(),
        k: "KEY".to_string(),
        aead: "xchacha20-poly1305".to_string(),
        nonce: "test_nonce".to_string(),
        ct: "test_ct".to_string(),
        disclosed: true,
    };
    let json = serde_json::to_string(&entry).unwrap();
    assert!(json.contains("\"disclosed\":true"));
}

#[test]
fn kv_entry_value_disclosed_false_omitted() {
    let entry = KvEntryValue {
        salt: "test_salt".to_string(),
        k: "KEY".to_string(),
        aead: "xchacha20-poly1305".to_string(),
        nonce: "test_nonce".to_string(),
        ct: "test_ct".to_string(),
        disclosed: false,
    };
    let json = serde_json::to_string(&entry).unwrap();
    assert!(!json.contains("disclosed"));
}

#[test]
fn kv_entry_value_deserialize_without_disclosed_defaults_false() {
    let json = r#"{"salt":"s","k":"K","aead":"xchacha20-poly1305","nonce":"n","ct":"c"}"#;
    let entry: KvEntryValue = serde_json::from_str(json).unwrap();
    assert!(!entry.disclosed);
}

#[test]
fn kv_entry_value_deserialize_with_disclosed_true() {
    let json =
        r#"{"salt":"s","k":"K","aead":"xchacha20-poly1305","nonce":"n","ct":"c","disclosed":true}"#;
    let entry: KvEntryValue = serde_json::from_str(json).unwrap();
    assert!(entry.disclosed);
}
