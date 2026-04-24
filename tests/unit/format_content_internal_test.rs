// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use secretenv::support::limits::MAX_JSON_DEPTH;

fn deeply_nested_json(depth: usize) -> String {
    let mut json = String::new();
    for _ in 0..depth {
        json.push_str(r#"{"nested":"#);
    }
    json.push_str(r#""value""#);
    for _ in 0..depth {
        json.push('}');
    }
    json
}

#[test]
fn file_enc_detect_rejects_non_json() {
    let result = FileEncContent::detect("not json".to_string());
    assert!(result.is_err());
}

#[test]
fn kv_enc_detect_rejects_json() {
    let result = KvEncContent::detect(r#"{"format":"secretenv.file@3"}"#.to_string());
    assert!(result.is_err());
}

#[test]
fn encrypted_content_detect_rejects_unknown() {
    let result = EncContent::detect("random text".to_string());
    assert!(result.is_err());
}

#[test]
fn file_enc_detect_rejects_json_exceeding_depth_limit() {
    let result = FileEncContent::detect(deeply_nested_json(MAX_JSON_DEPTH + 1));
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("nesting depth exceeds limit"));
}

#[test]
fn encrypted_content_detect_rejects_json_exceeding_depth_limit() {
    let result = EncContent::detect(deeply_nested_json(MAX_JSON_DEPTH + 1));
    assert!(result.is_err());
    let err = match result {
        Ok(_) => panic!("expected depth-limit error"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("nesting depth exceeds limit"));
}

#[test]
fn new_unchecked_preserves_content() {
    let content = "test content";
    let file = FileEncContent::new_unchecked(content.to_string());
    assert_eq!(file.as_str(), content);

    let kv = KvEncContent::new_unchecked(content.to_string());
    assert_eq!(kv.as_str(), content);
}
