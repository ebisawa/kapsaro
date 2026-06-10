// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for kv-enc canonical format

use crate::format::kv::enc::canonical::{build_canonical_bytes, extract_recipients_from_wrap};
use crate::format::kv::enc::parser::KvEncParser;
use crate::model::common::WrapItem;
use crate::model::kv_enc::header::KvWrap;
use crate::model::wire::algorithm;

#[test]
fn test_build_canonical_bytes() {
    let content =
        ":KAPSARO_KV 1\n:HEAD token0\n:WRAP token1\nKEY1 value1\nKEY2 value2\n:SIG sig_token\n";
    let parser = KvEncParser::new(content);
    let lines = parser.parse_all().unwrap();

    let canonical = build_canonical_bytes(&lines);
    let canonical = std::str::from_utf8(&canonical).unwrap();
    assert!(canonical.contains(":KAPSARO_KV 1"));
    assert!(canonical.contains(":HEAD token0"));
    assert!(canonical.contains(":WRAP token1"));
    assert!(canonical.contains("KEY1 value1"));
    assert!(canonical.contains("KEY2 value2"));
    assert!(!canonical.contains(":SIG"));
}

#[test]
fn test_extract_recipients_from_wrap() {
    let wrap = KvWrap {
        wrap: vec![
            WrapItem {
                recipient_handle: "alice@example.com".to_string(),
                kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
                alg: algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305.to_string(),
                enc: "dummy".to_string(),
                ct: "dummy".to_string(),
            },
            WrapItem {
                recipient_handle: "bob@example.com".to_string(),
                kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GH".to_string(),
                alg: algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305.to_string(),
                enc: "dummy".to_string(),
                ct: "dummy".to_string(),
            },
        ],
        removed_recipients: None,
    };

    let recipients = extract_recipients_from_wrap(&wrap);
    assert_eq!(recipients.len(), 2);
    assert_eq!(recipients[0], "alice@example.com");
    assert_eq!(recipients[1], "bob@example.com");
}
