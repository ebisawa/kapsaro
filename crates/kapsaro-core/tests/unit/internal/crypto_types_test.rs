// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::types::keys::XChaChaKey;
use kapsaro_core::Error;

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
