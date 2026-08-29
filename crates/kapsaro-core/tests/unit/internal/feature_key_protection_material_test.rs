// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for fresh PrivateKey protection salt generation

use crate::feature::key::protection::material::FreshPrivateKeyProtectionMaterial;

#[test]
fn test_generate_salt_lengths() {
    let material = FreshPrivateKeyProtectionMaterial::generate().unwrap();

    assert_eq!(material.ikm_salt.as_bytes().len(), 32);
    assert_eq!(material.hkdf_salt.as_bytes().len(), 32);
}

#[test]
fn test_generate_salt_randomness() {
    let material1 = FreshPrivateKeyProtectionMaterial::generate().unwrap();
    let material2 = FreshPrivateKeyProtectionMaterial::generate().unwrap();

    assert_ne!(material1.ikm_salt.as_bytes(), material2.ikm_salt.as_bytes());
    assert_ne!(
        material1.hkdf_salt.as_bytes(),
        material2.hkdf_salt.as_bytes()
    );
}
