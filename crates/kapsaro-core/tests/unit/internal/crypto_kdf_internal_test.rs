// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for HKDF-SHA256 PRK reuse.
//!
//! Verifies that extract-then-expand matches the one-shot HKDF interface.

use super::*;
use crate::crypto::types::data::{Ikm, Info};
use crate::crypto::types::primitives::{AsHkdfSalt, HkdfSalt};

/// The salt type `derive_hkdf_sha256_array` accepts, held still at compile time.
///
/// `AsHkdfSalt` is what the signature asks for, so applying this to `HkdfSalt`
/// states which salt the HKDF-Extract input is spelled with.
fn assert_hkdf_salt<T: AsHkdfSalt>() {}

#[test]
fn hkdf_extract_salt_is_the_hkdf_salt_type() {
    assert_hkdf_salt::<HkdfSalt>();
}

#[test]
fn hkdf_sha256_prk_expansion_matches_one_shot_derivation() {
    let ikm = Ikm::from(&[11u8; 32][..]);
    let salt = HkdfSalt::new([22u8; 32]);
    let info = Info::from_string("kapsaro:test:hkdf:info");

    let prk = derive_hkdf_sha256_prk(&ikm, salt.as_bytes());
    let from_prk = derive_hkdf_sha256_array_from_prk(&prk, &info).unwrap();
    let one_shot = derive_hkdf_sha256_array(&ikm, Some(&salt), &info).unwrap();

    assert_eq!(&from_prk[..], &one_shot[..]);
}

#[test]
fn hkdf_sha256_prk_expansion_is_bound_to_info() {
    let ikm = Ikm::from(&[33u8; 32][..]);
    let salt = HkdfSalt::new([44u8; 32]);
    let prk = derive_hkdf_sha256_prk(&ikm, salt.as_bytes());
    let info_a = Info::from_string("kapsaro:test:hkdf:info:a");
    let info_b = Info::from_string("kapsaro:test:hkdf:info:b");

    let key_a = derive_hkdf_sha256_array_from_prk(&prk, &info_a).unwrap();
    let key_b = derive_hkdf_sha256_array_from_prk(&prk, &info_b).unwrap();

    assert_ne!(&key_a[..], &key_b[..]);
}
