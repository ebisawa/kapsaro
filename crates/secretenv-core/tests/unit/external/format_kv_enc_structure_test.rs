// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV-enc structure validation tests
//!
//! Tests for strict structure validation (line order, counts, KEY format, duplicates)

use secretenv_core::cli_api::test_support::wire::kv::document::validate_kv_file_structure;
use secretenv_core::cli_api::test_support::wire::kv::enc::parser::KvEncParser;

#[test]
fn test_validate_valid_structure() {
    let content = ":SECRETENV_KV 9\n\
                   :HEAD token0\n\
                   :WRAP token1\n\
                   KEY1 token2\n\
                   KEY2 token3\n\
                   :SIG token4";
    let lines = KvEncParser::new(content).parse_all().unwrap();
    assert!(validate_kv_file_structure(&lines).is_ok());
}

#[test]
fn test_validate_missing_header() {
    let content = ":HEAD token0\n\
                   :WRAP token1\n\
                   KEY1 token2\n\
                   :SIG token3";
    let lines = KvEncParser::new(content).parse_all().unwrap();
    assert!(validate_kv_file_structure(&lines).is_err());
}

#[test]
fn test_validate_duplicate_header() {
    let content = ":SECRETENV_KV 9\n\
                   :HEAD token0\n\
                   :WRAP token1\n\
                   :SECRETENV_KV 9\n\
                   KEY1 token2\n\
                   :SIG token3";
    let lines = KvEncParser::new(content).parse_all().unwrap();
    assert!(validate_kv_file_structure(&lines).is_err());
}

#[test]
fn test_validate_header_not_first() {
    let content = ":HEAD token0\n\
                   :SECRETENV_KV 9\n\
                   :WRAP token1\n\
                   KEY1 token2\n\
                   :SIG token3";
    let lines = KvEncParser::new(content).parse_all().unwrap();
    assert!(validate_kv_file_structure(&lines).is_err());
}

#[test]
fn test_validate_duplicate_head() {
    let content = ":SECRETENV_KV 9\n\
                   :HEAD token0\n\
                   :HEAD token1\n\
                   :WRAP token2\n\
                   KEY1 token3\n\
                   :SIG token4";
    let lines = KvEncParser::new(content).parse_all().unwrap();
    assert!(validate_kv_file_structure(&lines).is_err());
}

#[test]
fn test_validate_head_not_second() {
    let content = ":SECRETENV_KV 9\n\
                   :WRAP token1\n\
                   :HEAD token0\n\
                   KEY1 token2\n\
                   :SIG token3";
    let lines = KvEncParser::new(content).parse_all().unwrap();
    assert!(validate_kv_file_structure(&lines).is_err());
}

#[test]
fn test_validate_duplicate_wrap() {
    let content = ":SECRETENV_KV 9\n\
                   :HEAD token0\n\
                   :WRAP token1\n\
                   :WRAP token2\n\
                   KEY1 token3\n\
                   :SIG token4";
    let lines = KvEncParser::new(content).parse_all().unwrap();
    assert!(validate_kv_file_structure(&lines).is_err());
}

#[test]
fn test_validate_wrap_not_third() {
    let content = ":SECRETENV_KV 9\n\
                   :HEAD token0\n\
                   KEY1 token2\n\
                   :WRAP token1\n\
                   :SIG token3";
    let lines = KvEncParser::new(content).parse_all().unwrap();
    assert!(validate_kv_file_structure(&lines).is_err());
}

#[test]
fn test_validate_duplicate_sig() {
    let content = ":SECRETENV_KV 9\n\
                   :HEAD token0\n\
                   :WRAP token1\n\
                   KEY1 token2\n\
                   :SIG token3\n\
                   :SIG token4";
    let lines = KvEncParser::new(content).parse_all().unwrap();
    assert!(validate_kv_file_structure(&lines).is_err());
}

#[test]
fn test_validate_sig_not_last() {
    let content = ":SECRETENV_KV 9\n\
                   :HEAD token0\n\
                   :WRAP token1\n\
                   :SIG token3\n\
                   KEY1 token2";
    let lines = KvEncParser::new(content).parse_all().unwrap();
    assert!(validate_kv_file_structure(&lines).is_err());
}

#[test]
fn test_validate_data_after_sig() {
    let content = ":SECRETENV_KV 9\n\
                   :HEAD token0\n\
                   :WRAP token1\n\
                   KEY1 token2\n\
                   :SIG token3\n\
                   KEY2 token4";
    let lines = KvEncParser::new(content).parse_all().unwrap();
    assert!(validate_kv_file_structure(&lines).is_err());
}

#[test]
fn test_validate_duplicate_key() {
    let content = ":SECRETENV_KV 9\n\
                   :HEAD token0\n\
                   :WRAP token1\n\
                   KEY1 token2\n\
                   KEY1 token3\n\
                   :SIG token4";
    let lines = KvEncParser::new(content).parse_all().unwrap();
    assert!(validate_kv_file_structure(&lines).is_err());
}

#[test]
fn test_validate_invalid_key_format_number_start() {
    let content = ":SECRETENV_KV 9\n\
                   :HEAD token0\n\
                   :WRAP token1\n\
                   1KEY token2\n\
                   :SIG token3";
    let lines = KvEncParser::new(content).parse_all().unwrap();
    assert!(validate_kv_file_structure(&lines).is_err());
}

#[test]
fn test_validate_invalid_key_format_colon() {
    let content = ":SECRETENV_KV 9\n\
                   :HEAD token0\n\
                   :WRAP token1\n\
                   KEY:NAME token2\n\
                   :SIG token3";
    let lines = KvEncParser::new(content).parse_all().unwrap();
    assert!(validate_kv_file_structure(&lines).is_err());
}

#[test]
fn test_validate_sig_with_empty_lines_after() {
    // Empty lines after :SIG are allowed
    let content = ":SECRETENV_KV 9\n\
                   :HEAD token0\n\
                   :WRAP token1\n\
                   KEY1 token2\n\
                   :SIG token3\n\
                   \n";
    let lines = KvEncParser::new(content).parse_all().unwrap();
    assert!(validate_kv_file_structure(&lines).is_ok());
}
