// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for artifact key-possession proof binding.
//!
//! Verifies that the HMAC proof is bound to the signer key statement ID.

use super::*;
use crate::crypto::types::keys::MasterKey;

const SIGNER_KID: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
const OTHER_SIGNER_KID: &str = "4Z8N6K1W3Q7RT5YH9M2PC4XV8D1B6FJA";

#[test]
fn key_possession_proof_binds_signer_kid() {
    let content_key = MasterKey::new([7u8; 32]);
    let body_bytes = br#"{"format":"secretenv:format:file-enc@6"}"#;

    let proof = build_key_possession_proof(body_bytes, &content_key, SIGNER_KID).unwrap();
    let other_proof =
        build_key_possession_proof(body_bytes, &content_key, OTHER_SIGNER_KID).unwrap();

    assert_ne!(proof.as_str(), other_proof.as_str());
    assert_ne!(proof.tag(), other_proof.tag());
}

#[test]
fn key_possession_verification_rejects_signer_kid_mismatch() {
    let content_key = MasterKey::new([9u8; 32]);
    let body_bytes = br#"{"format":"secretenv:format:file-enc@6"}"#;
    let proof = build_key_possession_proof(body_bytes, &content_key, SIGNER_KID).unwrap();

    verify_key_possession_proof(&proof, content_key.as_bytes(), body_bytes, SIGNER_KID).unwrap();

    let result =
        verify_key_possession_proof(&proof, content_key.as_bytes(), body_bytes, OTHER_SIGNER_KID);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("E_KEY_POSSESSION_MAC_INVALID"));
}
