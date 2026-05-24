// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for HKDF type-safe salt interface

use secretenv_core::cli_api::test_support::primitives::kdf::{
    derive_hkdf_sha256_array, derive_hkdf_sha256_bytes,
};
use secretenv_core::cli_api::test_support::primitives::types::data::{Ikm, Info};
use secretenv_core::cli_api::test_support::primitives::types::primitives::HkdfSalt;

#[test]
fn test_derive_hkdf_sha256_array_accepts_hkdf_salt() {
    let ikm = Ikm::from(&[0u8; 32][..]);
    let salt = HkdfSalt::new([1u8; 32]);
    let info = Info::from_string("test-info");

    let result = derive_hkdf_sha256_array(&ikm, Some(&salt), &info);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 32);
}

#[test]
fn test_derive_hkdf_sha256_array_none_salt() {
    let ikm = Ikm::from(&[0u8; 32][..]);
    let info = Info::from_string("test-info");

    let result = derive_hkdf_sha256_array::<HkdfSalt>(&ikm, None, &info);
    assert!(result.is_ok());
}

#[test]
fn test_derive_hkdf_sha256_array_different_salts_produce_different_keys() {
    let ikm = Ikm::from(&[0u8; 32][..]);
    let salt1 = HkdfSalt::new([1u8; 32]);
    let salt2 = HkdfSalt::new([2u8; 32]);
    let info = Info::from_string("test-info");

    let key1 = derive_hkdf_sha256_array(&ikm, Some(&salt1), &info).unwrap();
    let key2 = derive_hkdf_sha256_array(&ikm, Some(&salt2), &info).unwrap();

    assert_ne!(&key1[..], &key2[..]);
}

#[test]
fn test_derive_hkdf_sha256_bytes_returns_requested_length() {
    let ikm = Ikm::from(&[3u8; 32][..]);
    let salt = HkdfSalt::new([4u8; 32]);
    let info = Info::from_string("variable-length-info");

    let result = derive_hkdf_sha256_bytes(&ikm, Some(&salt), &info, 48).unwrap();

    assert_eq!(result.len(), 48);
}

#[test]
fn test_derive_hkdf_sha256_bytes_zero_length_is_allowed() {
    let ikm = Ikm::from(&[3u8; 32][..]);
    let info = Info::from_string("zero-length-info");

    let result = derive_hkdf_sha256_bytes::<HkdfSalt>(&ikm, None, &info, 0).unwrap();

    assert!(result.is_empty());
}

#[test]
fn test_derive_hkdf_sha256_bytes_rejects_hkdf_output_longer_than_limit() {
    let ikm = Ikm::from(&[3u8; 32][..]);
    let salt = HkdfSalt::new([4u8; 32]);
    let info = Info::from_string("too-long-info");

    let err = derive_hkdf_sha256_bytes(&ikm, Some(&salt), &info, 8161)
        .unwrap_err()
        .to_string();

    assert!(err.contains("HKDF expand failed"));
}
