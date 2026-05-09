// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::crypto::types::keys::XChaChaKey;
use crate::model::file_enc::{FileEncAlgorithm, FilePayloadHeader};
use crate::model::wire::{algorithm, format};
use crate::support::codec::base64_public::decode_base64url_nopad;
use uuid::Uuid;

#[test]
fn encrypt_file_payload_content_returns_valid_ciphertext() {
    let key_bytes = [0x42u8; 32];
    let key = XChaChaKey::from_slice(&key_bytes).unwrap();
    let plaintext = Plaintext::from(b"hello world".as_slice());
    let sid = Uuid::new_v4();
    let header = FilePayloadHeader {
        format: format::FILE_PAYLOAD_V5.to_string(),
        sid,
        alg: FileEncAlgorithm {
            aead: algorithm::AEAD_XCHACHA20_POLY1305.to_string(),
        },
    };

    let result = encrypt_file_payload_content(&plaintext, &key, &header, false, "test");
    assert!(result.is_ok());

    let ciphertext = result.unwrap();
    assert!(decode_base64url_nopad(&ciphertext.nonce, "nonce").is_ok());
    assert!(decode_base64url_nopad(&ciphertext.ct, "ct").is_ok());
    assert!(!ciphertext.ct.is_empty());
    assert!(!ciphertext.nonce.is_empty());
}
