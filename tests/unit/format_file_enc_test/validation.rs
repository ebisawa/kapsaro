// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{
    create_test_private_key, create_test_public_key, generate_ed25519_keypair,
    generate_x25519_keypair, recipients_and_members,
};
use crate::cli_common::ALICE_MEMBER_ID;
use crate::keygen_helpers::make_decrypted_private_key_plaintext;
use secretenv::feature::decrypt::file::decrypt_file_document;
use secretenv::feature::encrypt::file as file_enc;
use secretenv::feature::envelope::signature::SigningContext;
use secretenv::model::file_enc::VerifiedFileEncDocument;
use secretenv::model::verification::{SignatureVerificationProof, VerifyingKeySource};

#[test]
fn test_encrypt_file() {
    let (sk, pk) = generate_x25519_keypair([1u8; 32]);
    let pk_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        pk.as_bytes(),
    );
    let recipients_with_keys = vec![(
        ALICE_MEMBER_ID.to_string(),
        create_test_public_key(ALICE_MEMBER_ID, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD", &pk_b64),
    )];
    let (recipient_ids, members) = recipients_and_members(&recipients_with_keys);
    let signer_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
    let content = b"Hello, World! ".repeat(100);

    let file_enc_doc = file_enc::encrypt_file_document(
        &content,
        &recipient_ids,
        &members,
        &SigningContext {
            signing_key: &generate_ed25519_keypair([2u8; 32]),
            signer_kid,
            signer_pub: create_test_public_key("signer@test", signer_kid, "dummy"),
            debug: false,
        },
    )
    .unwrap();
    assert_eq!(
        file_enc_doc.protected.format,
        secretenv::model::identifiers::format::FILE_ENC_V3
    );

    let verified_doc = VerifiedFileEncDocument::new(
        file_enc_doc,
        SignatureVerificationProof::new(
            ALICE_MEMBER_ID.to_string(),
            signer_kid.to_string(),
            VerifyingKeySource::SignerPubEmbedded,
            Vec::new(),
        ),
    );
    let decrypted_key = make_decrypted_private_key_plaintext(
        create_test_private_key(&sk, &pk),
        ALICE_MEMBER_ID,
        signer_kid,
        "sha256:test",
    );
    let decrypted = decrypt_file_document(
        &verified_doc,
        ALICE_MEMBER_ID,
        signer_kid,
        &decrypted_key,
        false,
    )
    .unwrap();

    assert_eq!(decrypted.as_ref() as &[u8], content.as_slice());
}

#[test]
fn test_defence_in_depth_sid_mismatch() {
    let (sk, pk) = generate_x25519_keypair([1u8; 32]);
    let pk_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        pk.as_bytes(),
    );
    let recipients_with_keys = vec![(
        ALICE_MEMBER_ID.to_string(),
        create_test_public_key(ALICE_MEMBER_ID, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD", &pk_b64),
    )];
    let (recipient_ids, members) = recipients_and_members(&recipients_with_keys);
    let signer_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

    let mut file_enc_doc = file_enc::encrypt_file_document(
        b"Hello, World!",
        &recipient_ids,
        &members,
        &SigningContext {
            signing_key: &generate_ed25519_keypair([2u8; 32]),
            signer_kid,
            signer_pub: create_test_public_key("signer@test", signer_kid, "dummy"),
            debug: false,
        },
    )
    .unwrap();
    file_enc_doc.protected.payload.protected.sid = uuid::Uuid::new_v4();

    let verified_doc = VerifiedFileEncDocument::new(
        file_enc_doc,
        SignatureVerificationProof::new(
            ALICE_MEMBER_ID.to_string(),
            signer_kid.to_string(),
            VerifyingKeySource::SignerPubEmbedded,
            Vec::new(),
        ),
    );
    let decrypted_key = make_decrypted_private_key_plaintext(
        create_test_private_key(&sk, &pk),
        ALICE_MEMBER_ID,
        signer_kid,
        "sha256:test",
    );
    let result = decrypt_file_document(
        &verified_doc,
        ALICE_MEMBER_ID,
        signer_kid,
        &decrypted_key,
        false,
    );

    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("SID mismatch") || error_msg.contains("decrypt"));
}
