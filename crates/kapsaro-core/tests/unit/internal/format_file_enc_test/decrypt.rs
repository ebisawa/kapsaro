// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{
    b64url, build_test_private_key, build_test_public_key, decrypt_file_document_for_test,
    generate_ed25519_keypair, generate_x25519_keypair, recipients_and_members,
};
use crate::cli_api::test_support::storage::keystore::storage::load_public_key;
use crate::feature::context::crypto::{CryptoContext, SigningContext};
use crate::feature::decrypt::file::decrypt_file_document_with_context;
use crate::feature::encrypt::file as file_enc;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::model::public_key::PublicKey;
use crate::model::verification::{SignatureVerificationProof, VerifyingKeySource};
use crate::test_utils::keygen_helpers::build_verified_recipient_key;
use crate::test_utils::{setup_member_key_context, setup_test_keystore_from_fixtures};
use crate::test_utils::{ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE};
use std::path::Path;
use tempfile::TempDir;

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

/// Encrypt `b"test"` to a recipient derived from Alice's own key, and hand back the
/// document with the keystore-backed context that signed it and that the decryption
/// paths select their local key from.
fn encrypt_for_recipient(
    build_recipient: impl FnOnce(&CryptoContext, &Path) -> PublicKey,
) -> (VerifiedFileEncDocument, CryptoContext, TempDir) {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    let recipient = build_recipient(&key_ctx, &temp_dir.path().join("keys"));
    let signer_kid = key_ctx.kid().to_string();
    let recipient_handle = recipient.protected.subject_handle.clone();

    let file_enc_doc = file_enc::encrypt_file_document(
        b"test",
        &[recipient_handle],
        &[build_verified_recipient_key(recipient)],
        &SigningContext {
            signing_key: key_ctx.signing_key(),
            signer_kid: &signer_kid,
            signer_pub: build_test_public_key("signer@test", &signer_kid, "dummy"),
        },
    )
    .unwrap();

    let proof = SignatureVerificationProof::new_with_signer_public_key(
        ALICE_MEMBER_HANDLE.to_string(),
        signer_kid,
        file_enc_doc.signature.signer_pub.clone(),
        VerifyingKeySource::SignerPubEmbedded,
        Vec::new(),
    );
    let verified_doc = VerifiedFileEncDocument::new(file_enc_doc, proof);
    (verified_doc, key_ctx, temp_dir)
}

#[test]
fn test_decrypt_file_wrong_member_handle() {
    let (verified_doc, key_ctx, _temp_dir) = encrypt_for_recipient(|key_ctx, keystore_root| {
        load_public_key(keystore_root, ALICE_MEMBER_HANDLE, key_ctx.kid()).unwrap()
    });

    let result = decrypt_file_document_with_context(&verified_doc, BOB_MEMBER_HANDLE, &key_ctx);
    assert!(result.is_err());
}

#[test]
fn test_decrypt_file_wrong_key() {
    // Wrap to a KEM key Alice does not hold while keeping her handle and kid on the
    // wrap entry, so the local key is selected and then fails to open the wrap.
    let (verified_doc, key_ctx, _temp_dir) = encrypt_for_recipient(|key_ctx, _keystore_root| {
        let (_sk, pk) = generate_x25519_keypair([2u8; 32]);
        build_test_public_key(ALICE_MEMBER_HANDLE, key_ctx.kid(), &b64url(pk.as_bytes()))
    });

    let result = decrypt_file_document_with_context(&verified_doc, ALICE_MEMBER_HANDLE, &key_ctx);
    assert!(result.is_err());
}
