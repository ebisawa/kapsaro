// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{
    b64url, build_test_public_key, generate_ed25519_keypair, generate_x25519_keypair,
    recipients_and_members,
};
use crate::keygen_helpers::build_verified_recipient_key;
use crate::test_utils::{ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE};
use secretenv_core::cli_api::test_support::operations::encrypt::file as file_enc;
use secretenv_core::cli_api::test_support::operations::envelope::signature::SigningContext;
use uuid::Uuid;

#[test]
fn test_encrypt_file_basic() {
    let (_sk, pk) = generate_x25519_keypair([1u8; 32]);
    let pk_b64 = b64url(pk.as_bytes());
    let alice = build_test_public_key(
        ALICE_MEMBER_HANDLE,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        &pk_b64,
    );
    let recipients_with_keys = [(ALICE_MEMBER_HANDLE.to_string(), alice)];
    let recipient_handles: Vec<String> = recipients_with_keys
        .iter()
        .map(|(id, _)| id.clone())
        .collect();
    let members: Vec<_> = recipients_with_keys
        .iter()
        .map(|(_, pk)| build_verified_recipient_key(pk.clone()))
        .collect();

    let signer_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
    let file_enc_doc = file_enc::encrypt_file_document(
        b"Hello, World!",
        &recipient_handles,
        &members,
        &SigningContext {
            signing_key: &generate_ed25519_keypair([2u8; 32]),
            signer_kid,
            signer_pub: build_test_public_key("signer@test", signer_kid, "dummy"),
            debug: false,
        },
    )
    .unwrap();

    assert_eq!(
        file_enc_doc.protected.format,
        secretenv_core::cli_api::test_support::domain::wire::format::FILE_ENC_V5
    );
    assert_eq!(
        file_enc_doc.recipients(),
        vec![ALICE_MEMBER_HANDLE.to_string()]
    );

    let parsed: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&file_enc_doc).unwrap()).unwrap();
    assert_eq!(
        parsed["protected"]["payload"]["protected"]["format"],
        secretenv_core::cli_api::test_support::domain::wire::format::FILE_PAYLOAD_V5
    );
    assert_eq!(
        parsed["protected"]["payload"]["protected"]["alg"]["aead"],
        secretenv_core::cli_api::test_support::domain::wire::algorithm::AEAD_XCHACHA20_POLY1305
    );
    let wrap = parsed["protected"]["wrap"].as_array().unwrap();
    assert_eq!(wrap.len(), 1);
    assert_eq!(wrap[0]["rh"], ALICE_MEMBER_HANDLE);
    assert_eq!(wrap[0]["kid"], signer_kid);
    assert_eq!(
        parsed["signature"]["alg"],
        secretenv_core::cli_api::test_support::domain::wire::algorithm::SIGNATURE_ED25519
    );
    assert_eq!(parsed["signature"]["kid"], signer_kid);
    assert!(parsed["signature"]["sig"].is_string());
}

#[test]
fn test_encrypt_file_multiple_recipients() {
    let (_sk1, pk1) = generate_x25519_keypair([1u8; 32]);
    let (_sk2, pk2) = generate_x25519_keypair([2u8; 32]);
    let pk1_b64 = b64url(pk1.as_bytes());
    let pk2_b64 = b64url(pk2.as_bytes());
    let recipients_with_keys = [
        (
            ALICE_MEMBER_HANDLE.to_string(),
            build_test_public_key(
                ALICE_MEMBER_HANDLE,
                "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
                &pk1_b64,
            ),
        ),
        (
            BOB_MEMBER_HANDLE.to_string(),
            build_test_public_key(
                BOB_MEMBER_HANDLE,
                "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GH",
                &pk2_b64,
            ),
        ),
    ];
    let recipient_handles: Vec<String> = recipients_with_keys
        .iter()
        .map(|(id, _)| id.clone())
        .collect();
    let members: Vec<_> = recipients_with_keys
        .iter()
        .map(|(_, pk)| build_verified_recipient_key(pk.clone()))
        .collect();

    let file_enc_doc = file_enc::encrypt_file_document(
        b"Secret data",
        &recipient_handles,
        &members,
        &SigningContext {
            signing_key: &generate_ed25519_keypair([2u8; 32]),
            signer_kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            signer_pub: build_test_public_key(
                "signer@test",
                "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
                "dummy",
            ),
            debug: false,
        },
    )
    .unwrap();

    let recipients = file_enc_doc.recipients();
    assert_eq!(recipients.len(), 2);
    assert!(recipients.contains(&ALICE_MEMBER_HANDLE.to_string()));
    assert!(recipients.contains(&BOB_MEMBER_HANDLE.to_string()));

    let parsed: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&file_enc_doc).unwrap()).unwrap();
    let wrap = parsed["protected"]["wrap"].as_array().unwrap();
    assert_eq!(wrap.len(), 2);
    assert_eq!(
        wrap.iter()
            .find(|item| item["rh"] == ALICE_MEMBER_HANDLE)
            .unwrap()["kid"],
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"
    );
    assert_eq!(
        wrap.iter()
            .find(|item| item["rh"] == BOB_MEMBER_HANDLE)
            .unwrap()["kid"],
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GH"
    );
}

#[test]
fn test_encrypt_file_sid_is_uuid() {
    let (_sk, pk) = generate_x25519_keypair([1u8; 32]);
    let pk_b64 = b64url(pk.as_bytes());
    let recipients_with_keys = vec![(
        ALICE_MEMBER_HANDLE.to_string(),
        build_test_public_key(
            ALICE_MEMBER_HANDLE,
            "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            &pk_b64,
        ),
    )];
    let (recipient_handles, members) = recipients_and_members(&recipients_with_keys);

    let file_enc_doc = file_enc::encrypt_file_document(
        b"test",
        &recipient_handles,
        &members,
        &SigningContext {
            signing_key: &generate_ed25519_keypair([2u8; 32]),
            signer_kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            signer_pub: build_test_public_key(
                "signer@test",
                "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
                "dummy",
            ),
            debug: false,
        },
    )
    .unwrap();

    let parsed: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&file_enc_doc).unwrap()).unwrap();
    assert!(Uuid::parse_str(parsed["protected"]["sid"].as_str().unwrap()).is_ok());
}

#[test]
fn test_encrypt_file_deterministic_structure() {
    let (_sk, pk) = generate_x25519_keypair([1u8; 32]);
    let pk_b64 = b64url(pk.as_bytes());
    let alice = build_test_public_key(
        ALICE_MEMBER_HANDLE,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        &pk_b64,
    );
    let (recipient_handles1, members1) =
        recipients_and_members(&[(ALICE_MEMBER_HANDLE.to_string(), alice.clone())]);
    let (recipient_handles2, members2) =
        recipients_and_members(&[(ALICE_MEMBER_HANDLE.to_string(), alice)]);

    let signing_key = generate_ed25519_keypair([2u8; 32]);
    let signer_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
    let result1 = file_enc::encrypt_file_document(
        b"deterministic",
        &recipient_handles1,
        &members1,
        &SigningContext {
            signing_key: &signing_key,
            signer_kid,
            signer_pub: build_test_public_key("signer@test", signer_kid, "dummy"),
            debug: false,
        },
    )
    .unwrap();
    let result2 = file_enc::encrypt_file_document(
        b"deterministic",
        &recipient_handles2,
        &members2,
        &SigningContext {
            signing_key: &signing_key,
            signer_kid,
            signer_pub: build_test_public_key("signer@test", signer_kid, "dummy"),
            debug: false,
        },
    )
    .unwrap();

    let parsed1: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&result1).unwrap()).unwrap();
    let parsed2: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&result2).unwrap()).unwrap();
    assert_eq!(
        parsed1["protected"]["format"],
        parsed2["protected"]["format"]
    );
    assert_eq!(
        parsed1["protected"]["payload"]["protected"]["alg"]["aead"],
        parsed2["protected"]["payload"]["protected"]["alg"]["aead"]
    );
    assert_eq!(result1.recipients(), result2.recipients());
}

#[test]
fn test_encrypt_file_no_recipient_found() {
    let (recipient_handles, members) = recipients_and_members(&[]);
    let file_enc_doc = file_enc::encrypt_file_document(
        b"test",
        &recipient_handles,
        &members,
        &SigningContext {
            signing_key: &generate_ed25519_keypair([2u8; 32]),
            signer_kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            signer_pub: build_test_public_key(
                "signer@test",
                "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
                "dummy",
            ),
            debug: false,
        },
    )
    .unwrap();

    let parsed: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&file_enc_doc).unwrap()).unwrap();
    assert_eq!(parsed["protected"]["wrap"].as_array().unwrap().len(), 0);
}

#[test]
fn test_encrypt_file_signature_included() {
    let (_sk, pk) = generate_x25519_keypair([1u8; 32]);
    let pk_b64 = b64url(pk.as_bytes());
    let recipients_with_keys = vec![(
        ALICE_MEMBER_HANDLE.to_string(),
        build_test_public_key(
            ALICE_MEMBER_HANDLE,
            "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            &pk_b64,
        ),
    )];
    let (recipient_handles, members) = recipients_and_members(&recipients_with_keys);

    let file_enc_doc = file_enc::encrypt_file_document(
        b"test",
        &recipient_handles,
        &members,
        &SigningContext {
            signing_key: &generate_ed25519_keypair([2u8; 32]),
            signer_kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            signer_pub: build_test_public_key(
                "signer@test",
                "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
                "dummy",
            ),
            debug: false,
        },
    )
    .unwrap();

    let parsed: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&file_enc_doc).unwrap()).unwrap();
    let signature = &parsed["signature"];
    assert!(signature.is_object());
    assert_eq!(
        signature["alg"],
        secretenv_core::cli_api::test_support::domain::wire::algorithm::SIGNATURE_ED25519
    );
    assert_eq!(signature["kid"], "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD");
    assert!(!signature["sig"].as_str().unwrap().is_empty());
}
