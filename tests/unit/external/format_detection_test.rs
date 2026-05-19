// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Format detection tests
//!
//! Tests for:
//! - Automatic input type detection
//! - kv-plain detection (60% KEY=VALUE rule)
//! - kv-enc detection (:SECRETENV_KV 7 header)
//! - file-enc detection (JSON with "format": "secretenv:format:file-enc@5")

use secretenv_core::cli_api::test_support::helpers::limits::MAX_JSON_DEPTH;
use secretenv_core::cli_api::test_support::wire::detection::{detect_format, InputFormat};

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
fn test_detect_kv_enc_v7() {
    let content = ":SECRETENV_KV 7\n:HEAD eyJrZXkiOiJ2YWx1ZSJ9\n:WRAP eyJrZXkiOiJ2YWx1ZSJ9\nDATABASE_URL eyJrZXkiOiJ2YWx1ZSJ9\n";
    let format = detect_format(content).unwrap();
    assert_eq!(format, InputFormat::KvEnc);
}

#[test]
fn test_detect_file_enc_v5() {
    let content = r#"{"protected": {"format": "secretenv:format:file-enc@5", "sid": "550e8400-e29b-41d4-a716-446655440000", "wrap": [], "payload": {"protected": {"format": "secretenv:format:file-enc:payload@5", "sid": "550e8400-e29b-41d4-a716-446655440000", "alg": {"aead": "xchacha20-poly1305"}}, "encrypted": {"nonce": "...", "ct": "..."}}, "created_at": "2026-01-19T10:00:00Z", "updated_at": "2026-01-19T10:00:00Z"}, "signature": {"alg": "eddsa-ed25519", "kid": "...", "sig": "..."}}"#;
    let format = detect_format(content).unwrap();
    assert_eq!(format, InputFormat::FileEnc);
}

#[test]
fn test_detect_file_enc_rejects_json_exceeding_depth_limit() {
    let result = detect_format(&deeply_nested_json(MAX_JSON_DEPTH + 1));
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("nesting depth exceeds limit"));
}

#[test]
fn test_detect_kv_plain_simple() {
    let content = "DATABASE_URL=postgresql://localhost\nREDIS_URL=redis://localhost\n";
    let format = detect_format(content).unwrap();
    assert_eq!(format, InputFormat::KvPlain);
}

#[test]
fn test_detect_kv_plain_with_comments() {
    let content =
        "# Database config\nDATABASE_URL=postgresql://localhost\n\nREDIS_URL=redis://localhost\n";
    let format = detect_format(content).unwrap();
    assert_eq!(format, InputFormat::KvPlain);
}

#[test]
fn test_detect_kv_plain_with_empty_lines() {
    let content = "\n\nDATABASE_URL=value1\n\nREDIS_URL=value2\n\n";
    let format = detect_format(content).unwrap();
    assert_eq!(format, InputFormat::KvPlain);
}

#[test]
fn test_detect_kv_plain_60_percent_threshold() {
    // 3 KV lines, 1 non-KV line = 75% KV (> 60% threshold)
    let content = "DATABASE_URL=value\nREDIS_URL=value\nAPI_KEY=value\nNot a KV line\n";
    let format = detect_format(content).unwrap();
    assert_eq!(format, InputFormat::KvPlain);
}

#[test]
fn test_detect_unknown_below_threshold() {
    // 1 KV line, 1 non-KV line = 50% KV (< 60% threshold)
    let content = "DATABASE_URL=value\nNot a KV line\n";
    let format = detect_format(content).unwrap();
    assert_eq!(format, InputFormat::Unknown);
}

#[test]
fn test_detect_unknown_too_few_lines() {
    // Only 1 non-empty line (< 2 required)
    let content = "DATABASE_URL=value\n";
    let format = detect_format(content).unwrap();
    assert_eq!(format, InputFormat::Unknown);
}

#[test]
fn test_detect_empty_content() {
    let content = "";
    let format = detect_format(content).unwrap();
    assert_eq!(format, InputFormat::Unknown);
}
