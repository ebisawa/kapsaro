// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::crypto::types::keys::MasterKey;
use crate::model::kv_enc::entry::KvEntryValue;
use crate::model::wire::algorithm;
use uuid::Uuid;

#[test]
fn decrypt_entry_rejects_unsupported_header_aead_before_decoding_entry() {
    let entry = KvEntryValue {
        salt: "not-base64".to_string(),
        nonce: "not-base64".to_string(),
        ct: "not-base64".to_string(),
        disclosed: false,
    };
    let master_key = MasterKey::new([0u8; 32]);
    let sid = Uuid::new_v4();

    let result = decrypt_entry(
        &entry,
        "DATABASE_URL",
        "aes-256-gcm",
        &master_key,
        &sid,
        false,
        "test",
    );

    let message = result.unwrap_err().to_string();
    assert!(message.contains("Unsupported AEAD algorithm"));
}

#[test]
fn decrypt_entry_accepts_supported_header_aead_until_entry_decoding() {
    let entry = KvEntryValue {
        salt: "not-base64".to_string(),
        nonce: "not-base64".to_string(),
        ct: "not-base64".to_string(),
        disclosed: false,
    };
    let master_key = MasterKey::new([0u8; 32]);
    let sid = Uuid::new_v4();

    let result = decrypt_entry(
        &entry,
        "DATABASE_URL",
        algorithm::AEAD_XCHACHA20_POLY1305,
        &master_key,
        &sid,
        false,
        "test",
    );

    let message = result.unwrap_err().to_string();
    assert!(!message.contains("Unsupported AEAD algorithm"));
}
