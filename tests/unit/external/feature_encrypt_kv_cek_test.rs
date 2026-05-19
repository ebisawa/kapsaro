// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for CEK derivation

use secretenv_core::cli_api::test_support::helpers::codec::base64_public::encode_base64url_nopad;
use secretenv_core::cli_api::test_support::operations::envelope::cek::derive_cek;
use secretenv_core::cli_api::test_support::primitives::types::keys::MasterKey;
use uuid::Uuid;

fn test_sid() -> Uuid {
    Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap()
}

fn test_key() -> &'static str {
    "DATABASE_URL"
}

#[test]
fn test_derive_cek() {
    // Test CEK derivation from mk + salt + sid + key
    let mk = [0u8; 32]; // All zeros for simplicity
    let mk_obj = MasterKey::new(mk);
    // Fixed 32 bytes salt: all zeros
    let salt_bytes = [0u8; 32];
    let salt = encode_base64url_nopad(&salt_bytes);
    let sid = test_sid();

    let cek = derive_cek(&mk_obj, &salt, &sid, test_key(), false).unwrap();

    // Should be 32 bytes
    assert_eq!(cek.as_bytes().len(), 32);

    // Should be deterministic
    let cek2 = derive_cek(&mk_obj, &salt, &sid, test_key(), false).unwrap();
    assert_eq!(cek.as_bytes(), cek2.as_bytes());
}

#[test]
fn test_derive_cek_different_salt() {
    // Different salt should produce different cek
    let mk = [0u8; 32];
    let mk_obj = MasterKey::new(mk);
    let salt1_bytes = [0u8; 32];
    let salt2_bytes = [1u8; 32];
    let salt1 = encode_base64url_nopad(&salt1_bytes);
    let salt2 = encode_base64url_nopad(&salt2_bytes);
    let sid = test_sid();

    let cek1 = derive_cek(&mk_obj, &salt1, &sid, test_key(), false).unwrap();
    let cek2 = derive_cek(&mk_obj, &salt2, &sid, test_key(), false).unwrap();

    assert_ne!(cek1.as_bytes(), cek2.as_bytes());
}

#[test]
fn test_derive_cek_different_mk() {
    // Different mk should produce different cek
    let mk1 = [0u8; 32];
    let mk1_obj = MasterKey::new(mk1);
    let mk2 = [1u8; 32];
    let mk2_obj = MasterKey::new(mk2);
    let salt_bytes = [0u8; 32];
    let salt = encode_base64url_nopad(&salt_bytes);
    let sid = test_sid();

    let cek1 = derive_cek(&mk1_obj, &salt, &sid, test_key(), false).unwrap();
    let cek2 = derive_cek(&mk2_obj, &salt, &sid, test_key(), false).unwrap();

    assert_ne!(cek1.as_bytes(), cek2.as_bytes());
}

#[test]
fn test_derive_cek_different_sid() {
    // Different sid should produce different cek
    let mk = [0u8; 32];
    let mk_obj = MasterKey::new(mk);
    let salt_bytes = [0u8; 32];
    let salt = encode_base64url_nopad(&salt_bytes);
    let sid1 = test_sid();
    let sid2 = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();

    let cek1 = derive_cek(&mk_obj, &salt, &sid1, test_key(), false).unwrap();
    let cek2 = derive_cek(&mk_obj, &salt, &sid2, test_key(), false).unwrap();

    assert_ne!(cek1.as_bytes(), cek2.as_bytes());
}

#[test]
fn test_derive_cek_different_key() {
    let mk = [0u8; 32];
    let mk_obj = MasterKey::new(mk);
    let salt_bytes = [0u8; 32];
    let salt = encode_base64url_nopad(&salt_bytes);
    let sid = test_sid();

    let cek1 = derive_cek(&mk_obj, &salt, &sid, "DATABASE_URL", false).unwrap();
    let cek2 = derive_cek(&mk_obj, &salt, &sid, "API_KEY", false).unwrap();

    assert_ne!(cek1.as_bytes(), cek2.as_bytes());
}

#[test]
fn test_derive_cek_invalid_salt_length() {
    // Salt with wrong length should fail
    let mk = [0u8; 32];
    let mk_obj = MasterKey::new(mk);
    // 8 bytes instead of 32 bytes
    let salt_bytes = [0u8; 8];
    let salt = encode_base64url_nopad(&salt_bytes);
    let sid = test_sid();

    let result = derive_cek(&mk_obj, &salt, &sid, test_key(), false);
    assert!(result.is_err());
}
