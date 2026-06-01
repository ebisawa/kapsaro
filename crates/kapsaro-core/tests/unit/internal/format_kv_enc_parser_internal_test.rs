// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::support::limits::{MAX_KV_ENC_FILE_SIZE, MAX_KV_KEY_LINES};

#[test]
fn test_file_size_limit_exceeded() {
    let oversized = "A".repeat(MAX_KV_ENC_FILE_SIZE + 1);
    let parser = KvEncParser::new(&oversized);
    let result = parser.parse_all();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("exceeds maximum size limit"),
        "unexpected error: {}",
        err
    );
}

#[test]
fn test_file_size_at_limit_is_accepted() {
    let content = "A".repeat(MAX_KV_ENC_FILE_SIZE);
    let parser = KvEncParser::new(&content);
    let result = parser.parse_all();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        !err.contains("exceeds maximum size limit"),
        "should not fail on size limit: {}",
        err
    );
}

#[test]
fn test_key_line_count_limit_exceeded() {
    let mut content = String::from(":KAPSARO_KV 1\n:HEAD token\n:WRAP token\n");
    for i in 0..=MAX_KV_KEY_LINES {
        content.push_str(&format!("KEY_{} value\n", i));
    }
    content.push_str(":SIG sigtoken\n");

    let parser = KvEncParser::new(&content);
    let result = parser.parse_all();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("exceeds maximum KEY line count"),
        "unexpected error: {}",
        err
    );
}

#[test]
fn test_key_line_count_at_limit_is_accepted() {
    let mut content = String::from(":KAPSARO_KV 1\n:HEAD token\n:WRAP token\n");
    for i in 0..MAX_KV_KEY_LINES {
        content.push_str(&format!("KEY_{} value\n", i));
    }
    content.push_str(":SIG sigtoken\n");

    let parser = KvEncParser::new(&content);
    let result = parser.parse_all();
    assert!(result.is_ok());
}
