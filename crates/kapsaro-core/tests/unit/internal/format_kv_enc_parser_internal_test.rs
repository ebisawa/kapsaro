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

/// Build a syntactically valid document padded to exactly `size` bytes.
fn kv_document_of_size(size: usize) -> String {
    let prefix = ":KAPSARO_KV 1\n:HEAD head\n:WRAP wrap\nPADDING ";
    let suffix = "\n:SIG sig\n";
    let padding = size - prefix.len() - suffix.len();
    format!("{}{}{}", prefix, "A".repeat(padding), suffix)
}

#[test]
fn test_file_size_at_limit_is_accepted() {
    let content = kv_document_of_size(MAX_KV_ENC_FILE_SIZE);

    let lines = KvEncParser::new(&content).parse_all().unwrap();

    assert_eq!(content.len(), MAX_KV_ENC_FILE_SIZE);
    assert!(!lines.is_empty());
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
