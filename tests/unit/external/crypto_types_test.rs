// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv::crypto::types::keys::{Cek, MasterKey, XChaChaKey};
use secretenv::crypto::types::primitives::{HkdfSalt, KvSalt, PrivateKeyIkmSalt, XChaChaNonce};
use secretenv::Error;

fn error_message<T>(result: Result<T, Error>) -> String {
    match result {
        Ok(_) => panic!("expected error"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn test_xchacha_key_from_slice_accepts_exact_length() {
    let bytes = [7u8; 32];

    let key = XChaChaKey::from_slice(&bytes).unwrap();

    assert_eq!(key.as_bytes(), &bytes);
}

#[test]
fn test_xchacha_key_from_slice_rejects_wrong_length() {
    let error = error_message(XChaChaKey::from_slice(&[7u8; 31]));

    assert!(
        error.contains("Invalid XChaCha key length: expected 32 bytes, got 31"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_master_key_from_slice_accepts_exact_length() {
    let bytes = [8u8; 32];

    let key = MasterKey::from_slice(&bytes).unwrap();

    assert_eq!(key.as_bytes(), &bytes);
}

#[test]
fn test_cek_from_slice_rejects_wrong_length() {
    let error = error_message(Cek::from_slice(&[9u8; 33]));

    assert!(
        error.contains("Invalid CEK length: expected 32 bytes, got 33"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_xchacha_nonce_from_slice_accepts_exact_length() {
    let bytes = [10u8; XChaChaNonce::SIZE];

    let nonce = XChaChaNonce::from_slice(&bytes).unwrap();

    assert_eq!(nonce.as_bytes(), &bytes);
}

#[test]
fn test_xchacha_nonce_from_slice_rejects_wrong_length() {
    let error = error_message(XChaChaNonce::from_slice(&[10u8; 23]));

    assert!(
        error.contains("Invalid XChaCha nonce length: expected 24 bytes, got 23"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_salt_from_slice_accepts_exact_lengths() {
    let bytes = [11u8; 32];

    assert_eq!(KvSalt::from_slice(&bytes).unwrap().as_bytes(), &bytes);
    assert_eq!(HkdfSalt::from_slice(&bytes).unwrap().as_bytes(), &bytes);
    assert_eq!(
        PrivateKeyIkmSalt::from_slice(&bytes).unwrap().as_bytes(),
        &bytes
    );
}

#[test]
fn test_hkdf_salt_from_slice_rejects_wrong_length() {
    let error = error_message(HkdfSalt::from_slice(&[11u8; 30]));

    assert!(
        error.contains("Invalid HKDF salt length: expected 32 bytes, got 30"),
        "unexpected error: {error}"
    );
}
