// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{
    b64url, build_test_private_key, build_test_public_key, decrypt_file_document_for_test,
    generate_ed25519_keypair, generate_x25519_keypair, recipients_and_members,
};
use crate::keygen_helpers::build_verified_private_key;
use crate::test_utils::{ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE};
use secretenv::feature::decrypt::file::decrypt_file_document;
use secretenv::feature::encrypt::file as file_enc;
use secretenv::feature::envelope::signature::SigningContext;
use secretenv::model::file_enc::VerifiedFileEncDocument;
use secretenv::model::verification::{SignatureVerificationProof, VerifyingKeySource};

#[test]
fn test_decrypt_file_roundtrip() {
    let (sk, pk) = generate_x25519_keypair([1u8; 32]);
    let pk_b64 = b64url(pk.as_bytes());
    let alice = build_test_public_key(
        ALICE_MEMBER_HANDLE,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        &pk_b64,
    );
    let alice_priv = build_test_private_key(&sk, &pk);
    let (recipient_handles, members) =
        recipients_and_members(&[(ALICE_MEMBER_HANDLE.to_string(), alice)]);
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

    let decrypted = decrypt_file_document_for_test(
        &file_enc_doc,
        ALICE_MEMBER_HANDLE,
        signer_kid,
        &alice_priv,
        signer_kid,
    );
    assert_eq!(b"Hello, World!", decrypted.as_slice());
}

#[test]
fn test_decrypt_file_multiple_recipients() {
    let (sk1, pk1) = generate_x25519_keypair([1u8; 32]);
    let (sk2, pk2) = generate_x25519_keypair([2u8; 32]);
    let pk1_b64 = b64url(pk1.as_bytes());
    let pk2_b64 = b64url(pk2.as_bytes());
    let recipients_with_keys = vec![
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
    let (recipient_handles, members) = recipients_and_members(&recipients_with_keys);
    let signer_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
    let file_enc_doc = file_enc::encrypt_file_document(
        b"Secret data for both",
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

    let decrypted_alice = decrypt_file_document_for_test(
        &file_enc_doc,
        ALICE_MEMBER_HANDLE,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        &build_test_private_key(&sk1, &pk1),
        signer_kid,
    );
    let decrypted_bob = decrypt_file_document_for_test(
        &file_enc_doc,
        BOB_MEMBER_HANDLE,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GH",
        &build_test_private_key(&sk2, &pk2),
        signer_kid,
    );

    assert_eq!(b"Secret data for both", decrypted_alice.as_slice());
    assert_eq!(b"Secret data for both", decrypted_bob.as_slice());
}

#[test]
fn test_decrypt_file_empty_content() {
    let (sk, pk) = generate_x25519_keypair([1u8; 32]);
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
    let signer_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
    let file_enc_doc = file_enc::encrypt_file_document(
        b"",
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

    let decrypted = decrypt_file_document_for_test(
        &file_enc_doc,
        ALICE_MEMBER_HANDLE,
        signer_kid,
        &build_test_private_key(&sk, &pk),
        signer_kid,
    );
    assert_eq!(b"", decrypted.as_slice());
}

#[test]
fn test_decrypt_file_large_content() {
    let content = vec![0xAB; 1024 * 1024];
    let (sk, pk) = generate_x25519_keypair([1u8; 32]);
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
    let signer_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
    let file_enc_doc = file_enc::encrypt_file_document(
        &content,
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

    let decrypted = decrypt_file_document_for_test(
        &file_enc_doc,
        ALICE_MEMBER_HANDLE,
        signer_kid,
        &build_test_private_key(&sk, &pk),
        signer_kid,
    );
    assert_eq!(content.as_slice(), decrypted.as_ref() as &[u8]);
}

#[test]
fn test_decrypt_file_wrong_member_handle() {
    let (sk, pk) = generate_x25519_keypair([1u8; 32]);
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
    let signer_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
    let file_enc_doc = file_enc::encrypt_file_document(
        b"test",
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

    let verified_doc = VerifiedFileEncDocument::new(
        file_enc_doc.clone(),
        SignatureVerificationProof::new(
            ALICE_MEMBER_HANDLE.to_string(),
            signer_kid.to_string(),
            VerifyingKeySource::SignerPubEmbedded,
            Vec::new(),
        ),
    );
    let decrypted_key = build_verified_private_key(
        &build_test_private_key(&sk, &pk),
        BOB_MEMBER_HANDLE,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GJ",
        "SHA256:test",
    );

    let result = decrypt_file_document(
        &verified_doc,
        BOB_MEMBER_HANDLE,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GJ",
        &decrypted_key,
        false,
    );
    assert!(result.is_err());
}

#[test]
fn test_decrypt_file_wrong_key() {
    let (_sk1, pk1) = generate_x25519_keypair([1u8; 32]);
    let (sk2, pk2) = generate_x25519_keypair([2u8; 32]);
    let pk1_b64 = b64url(pk1.as_bytes());
    let recipients_with_keys = vec![(
        ALICE_MEMBER_HANDLE.to_string(),
        build_test_public_key(
            ALICE_MEMBER_HANDLE,
            "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            &pk1_b64,
        ),
    )];
    let (recipient_handles, members) = recipients_and_members(&recipients_with_keys);
    let signer_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
    let file_enc_doc = file_enc::encrypt_file_document(
        b"test",
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
    let verified_doc = VerifiedFileEncDocument::new(
        file_enc_doc.clone(),
        SignatureVerificationProof::new(
            ALICE_MEMBER_HANDLE.to_string(),
            signer_kid.to_string(),
            VerifyingKeySource::SignerPubEmbedded,
            Vec::new(),
        ),
    );
    let wrong_key = build_verified_private_key(
        &build_test_private_key(&sk2, &pk2),
        ALICE_MEMBER_HANDLE,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        "SHA256:test",
    );

    let result = decrypt_file_document(
        &verified_doc,
        ALICE_MEMBER_HANDLE,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        &wrong_key,
        false,
    );
    assert!(result.is_err());
}
