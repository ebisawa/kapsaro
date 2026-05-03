// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Validation tests for feature/decrypt/unwrap functions
//!
//! Tests validation logic in `decode_wrap_item_fields` and `parse_master_key_from_plaintext`.

use secretenv::crypto::types::data::Plaintext;
use secretenv::feature::envelope::unwrap::{
    decode_wrap_item_fields, parse_master_key_from_plaintext,
};
use secretenv::model::common::WrapItem;
use zeroize::Zeroizing;

/// Test that `decode_wrap_item_fields` returns an error for an unsupported algorithm.
#[test]
fn test_decode_wrap_item_fields_unsupported_alg() {
    let wrap_item = WrapItem {
        recipient_handle: "alice@example.com".to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GK".to_string(),
        alg: "unsupported-alg-99".to_string(),
        enc: "AAAA".to_string(),
        ct: "BBBB".to_string(),
    };

    let result = decode_wrap_item_fields(&wrap_item);
    assert!(result.is_err(), "Should fail for unsupported algorithm");

    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("Unsupported HPKE algorithm"),
        "Error should mention 'Unsupported HPKE algorithm', got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("unsupported-alg-99"),
        "Error should contain the unsupported algorithm name, got: {}",
        err_msg
    );
}

/// Test that `parse_master_key_from_plaintext` returns an error when given wrong-length data.
#[test]
fn test_parse_master_key_from_plaintext_wrong_length() {
    // 16 bytes instead of expected 32
    let short_data = vec![0xABu8; 16];
    let plaintext = Zeroizing::new(Plaintext::new(short_data));

    let result = parse_master_key_from_plaintext(plaintext);
    assert!(result.is_err(), "Should fail for wrong-length plaintext");

    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("Expected error but got Ok"),
    };
    let err_msg = format!("{}", err);
    assert!(
        err_msg.contains("Invalid master key length"),
        "Error should mention 'Invalid master key length', got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("16"),
        "Error should mention actual length 16, got: {}",
        err_msg
    );
}

/// Test that `parse_master_key_from_plaintext` succeeds with correct 32-byte data.
#[test]
fn test_parse_master_key_from_plaintext() {
    let key_bytes = [0x42u8; 32];
    let plaintext = Zeroizing::new(Plaintext::new(key_bytes.to_vec()));

    let result = parse_master_key_from_plaintext(plaintext);
    assert!(result.is_ok(), "Should succeed for 32-byte plaintext");

    let master_key = result.unwrap();
    assert_eq!(
        master_key.as_bytes(),
        &key_bytes,
        "Master key bytes should match input"
    );
}
