// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for artifact key-possession proof binding.
//!
//! Verifies that the HMAC proof is bound to the signer key statement ID.

use super::*;
use crate::crypto::types::keys::MacKey;
use crate::format::signature::{build_artifact_signature_input, build_key_possession_mac_message};
use crate::model::wire::{
    algorithm,
    context::{MAC_DOMAIN_KEY_POSSESSION_V2, SIG_DOMAIN_ARTIFACT_SIGNATURE_V2},
};

const SIGNER_KID: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
const OTHER_SIGNER_KID: &str = "4Z8N6K1W3Q7RT5YH9M2PC4XV8D1B6FJA";

#[test]
fn key_possession_mac_message_uses_domain_and_framed_fields() {
    let body_bytes = b"abc";
    let message = build_key_possession_mac_message(body_bytes, "XY");
    let expected = format!("{MAC_DOMAIN_KEY_POSSESSION_V2}3:abc2:XY");

    assert_eq!(message, expected.as_bytes());
}

#[test]
fn key_possession_sig_input_uses_separate_domain_and_framed_fields() {
    let proof =
        KeyPossessionProof::parse("hmac-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .unwrap();
    let input = build_artifact_signature_input(
        algorithm::SIGNATURE_ED25519,
        SIGNER_KID,
        b"body",
        proof.as_str(),
    )
    .unwrap();
    let header = format!(
        r#"{{"alg":"{}","kid":"{}"}}"#,
        algorithm::SIGNATURE_ED25519,
        SIGNER_KID
    );
    let expected = format!(
        "{SIG_DOMAIN_ARTIFACT_SIGNATURE_V2}{}:{header}4:body{}:{}",
        header.len(),
        proof.as_str().len(),
        proof.as_str()
    );

    assert_eq!(input, expected.as_bytes());
}

#[test]
fn artifact_signature_input_binds_signature_header_values() {
    let proof =
        KeyPossessionProof::parse("hmac-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .unwrap();
    let base = build_artifact_signature_input(
        algorithm::SIGNATURE_ED25519,
        SIGNER_KID,
        b"body",
        proof.as_str(),
    )
    .unwrap();
    let other_kid = build_artifact_signature_input(
        algorithm::SIGNATURE_ED25519,
        OTHER_SIGNER_KID,
        b"body",
        proof.as_str(),
    )
    .unwrap();
    let other_alg =
        build_artifact_signature_input("future-ed25519", SIGNER_KID, b"body", proof.as_str())
            .unwrap();

    assert_ne!(base, other_kid);
    assert_ne!(base, other_alg);
}

#[test]
fn key_possession_proof_binds_signer_kid() {
    let mac_key = MacKey::new([7u8; 32]);
    let body_bytes = br#"{"format":"secretenv:format:file-enc@7"}"#;

    let proof =
        build_key_possession_proof("file", body_bytes, &mac_key, SIGNER_KID, false).unwrap();
    let other_proof =
        build_key_possession_proof("file", body_bytes, &mac_key, OTHER_SIGNER_KID, false).unwrap();

    assert_ne!(proof.as_str(), other_proof.as_str());
    assert_ne!(proof.tag(), other_proof.tag());
}

#[test]
fn key_possession_verification_rejects_signer_kid_mismatch() {
    let mac_key = MacKey::new([9u8; 32]);
    let body_bytes = br#"{"format":"secretenv:format:file-enc@7"}"#;
    let proof =
        build_key_possession_proof("file", body_bytes, &mac_key, SIGNER_KID, false).unwrap();

    verify_key_possession_proof("file", &proof, &mac_key, body_bytes, SIGNER_KID, false).unwrap();

    let result = verify_key_possession_proof(
        "file",
        &proof,
        &mac_key,
        body_bytes,
        OTHER_SIGNER_KID,
        false,
    );

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("E_KEY_POSSESSION_MAC_INVALID"));
}
