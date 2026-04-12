// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for HKDF type-safe salt interface

use secretenv::crypto::kdf::expand_to_array;
use secretenv::crypto::types::data::{Ikm, Info};
use secretenv::crypto::types::primitives::{HkdfSalt, KvSalt};

#[test]
fn test_expand_to_array_accepts_hkdf_salt() {
    let ikm = Ikm::from(&[0u8; 32][..]);
    let salt = HkdfSalt::new([1u8; 32]);
    let info = Info::from_string("test-info");

    let result = expand_to_array(&ikm, Some(&salt), &info);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().as_bytes().len(), 32);
}

#[test]
fn test_expand_to_array_accepts_kv_salt() {
    let ikm = Ikm::from(&[0u8; 32][..]);
    let salt = KvSalt::new([2u8; 32]);
    let info = Info::from_string("test-info");

    let result = expand_to_array(&ikm, Some(&salt), &info);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().as_bytes().len(), 32);
}

#[test]
fn test_expand_to_array_none_salt() {
    let ikm = Ikm::from(&[0u8; 32][..]);
    let info = Info::from_string("test-info");

    let result = expand_to_array::<HkdfSalt>(&ikm, None, &info);
    assert!(result.is_ok());
}

#[test]
fn test_expand_to_array_different_salts_produce_different_keys() {
    let ikm = Ikm::from(&[0u8; 32][..]);
    let salt1 = HkdfSalt::new([1u8; 32]);
    let salt2 = HkdfSalt::new([2u8; 32]);
    let info = Info::from_string("test-info");

    let key1 = expand_to_array(&ikm, Some(&salt1), &info).unwrap();
    let key2 = expand_to_array(&ikm, Some(&salt2), &info).unwrap();

    assert_ne!(key1.as_bytes(), key2.as_bytes());
}
