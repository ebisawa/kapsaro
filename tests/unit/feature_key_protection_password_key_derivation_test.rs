// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for password-based key derivation (Argon2id + HKDF-SHA256)

use secretenv::crypto::types::primitives::{HkdfSalt, PrivateKeyIkmSalt};
use secretenv::feature::key::protection::password_key_derivation::{
    derive_key_from_password, generate_hkdf_salt, generate_ikm_salt,
};

#[test]
fn test_derive_key_from_password_deterministic() {
    let ikm_salt = PrivateKeyIkmSalt::new([1u8; 32]);
    let hkdf_salt = HkdfSalt::new([2u8; 32]);
    let kid = "test-kid-001";
    let password = "correct horse battery staple";

    let key1 = derive_key_from_password(password, &ikm_salt, &hkdf_salt, kid, false).unwrap();
    let key2 = derive_key_from_password(password, &ikm_salt, &hkdf_salt, kid, false).unwrap();

    assert_eq!(key1.as_bytes().len(), 32);
    assert_eq!(key1.as_bytes(), key2.as_bytes());
}

#[test]
fn test_derive_key_different_passwords_differ() {
    let ikm_salt = PrivateKeyIkmSalt::new([3u8; 32]);
    let hkdf_salt = HkdfSalt::new([4u8; 32]);
    let kid = "test-kid-002";

    let key1 = derive_key_from_password("password-a", &ikm_salt, &hkdf_salt, kid, false).unwrap();
    let key2 = derive_key_from_password("password-b", &ikm_salt, &hkdf_salt, kid, false).unwrap();

    assert_ne!(key1.as_bytes(), key2.as_bytes());
}

#[test]
fn test_derive_key_different_ikm_salts_differ() {
    let salt1 = PrivateKeyIkmSalt::new([5u8; 32]);
    let salt2 = PrivateKeyIkmSalt::new([6u8; 32]);
    let hkdf_salt = HkdfSalt::new([7u8; 32]);
    let kid = "test-kid-003";
    let password = "same-password";

    let key1 = derive_key_from_password(password, &salt1, &hkdf_salt, kid, false).unwrap();
    let key2 = derive_key_from_password(password, &salt2, &hkdf_salt, kid, false).unwrap();

    assert_ne!(key1.as_bytes(), key2.as_bytes());
}

#[test]
fn test_generate_salt_lengths() {
    assert_eq!(generate_ikm_salt().as_bytes().len(), 32);
    assert_eq!(generate_hkdf_salt().as_bytes().len(), 32);
}

#[test]
fn test_generate_salt_randomness() {
    let ikm_salt1 = generate_ikm_salt();
    let ikm_salt2 = generate_ikm_salt();
    let hkdf_salt1 = generate_hkdf_salt();
    let hkdf_salt2 = generate_hkdf_salt();
    assert_ne!(ikm_salt1.as_bytes(), ikm_salt2.as_bytes());
    assert_ne!(hkdf_salt1.as_bytes(), hkdf_salt2.as_bytes());
}

#[test]
fn test_derive_key_different_kids_differ() {
    let ikm_salt = PrivateKeyIkmSalt::new([8u8; 32]);
    let hkdf_salt = HkdfSalt::new([9u8; 32]);
    let password = "same-password-for-both";

    let key1 = derive_key_from_password(password, &ikm_salt, &hkdf_salt, "kid-aaa", false).unwrap();
    let key2 = derive_key_from_password(password, &ikm_salt, &hkdf_salt, "kid-bbb", false).unwrap();

    assert_ne!(
        key1.as_bytes(),
        key2.as_bytes(),
        "Same password and salt with different kids must produce different keys"
    );
}

#[test]
fn test_derive_key_different_hkdf_salts_differ() {
    let ikm_salt = PrivateKeyIkmSalt::new([10u8; 32]);
    let hkdf_salt1 = HkdfSalt::new([11u8; 32]);
    let hkdf_salt2 = HkdfSalt::new([12u8; 32]);

    let key1 = derive_key_from_password("same-password", &ikm_salt, &hkdf_salt1, "kid-ccc", false)
        .unwrap();
    let key2 = derive_key_from_password("same-password", &ikm_salt, &hkdf_salt2, "kid-ccc", false)
        .unwrap();

    assert_ne!(key1.as_bytes(), key2.as_bytes());
}
