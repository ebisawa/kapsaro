// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/decrypt module
//!
//! Tests for file-enc decryption.

use crate::cli_common::ALICE_MEMBER_ID;
use crate::keygen_helpers::make_verified_members;
use crate::test_utils::{setup_member_key_context, setup_test_keystore_from_fixtures};
use secretenv::feature::context::crypto::CryptoContext;
use secretenv::feature::decrypt::decrypt_document;
use secretenv::feature::decrypt::file::decrypt_file_document;
use secretenv::feature::encrypt::file::encrypt_file_document;
use secretenv::feature::envelope::signature::SigningContext;
use secretenv::feature::verify::file::verify_file_document;
use secretenv::format::content::FileEncContent;
use secretenv::io::keystore::storage::{list_kids, load_public_key};
use secretenv::model::file_enc::VerifiedFileEncDocument;
use secretenv::model::verification::{SignatureVerificationProof, VerifyingKeySource};
use tempfile::TempDir;

#[test]
fn test_file_enc_content_detect_accepts_file_enc() {
    // Create file-enc content
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    // Get public key from keystore first
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();

    // Load CryptoContext to get signing key
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);

    let content = b"Hello, World!";
    let recipient_ids = vec![ALICE_MEMBER_ID.to_string()];
    let members = make_verified_members(std::slice::from_ref(&public_key));

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_ids,
        &members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: kid,
            signer_pub: public_key.clone(),
            debug: false,
        },
    )
    .unwrap();

    let encrypted_json = serde_json::to_string(&file_enc_doc).unwrap();

    // Detect format via FileEncContent
    let file_enc = FileEncContent::detect(encrypted_json);
    assert!(
        file_enc.is_ok(),
        "FileEncContent::detect should accept file-enc format"
    );
}

#[test]
fn test_file_enc_content_detect_rejects_plain_kv() {
    // Plain kv format should be rejected
    let plain_kv = "DATABASE_URL=postgres://localhost\nAPI_KEY=secret\n";
    let result = FileEncContent::detect(plain_kv.to_string());
    assert!(result.is_err());
}

#[test]
fn test_file_enc_content_detect_rejects_kv_enc() {
    // kv-enc format should be rejected by FileEncContent::detect
    let kv_enc = ":SECRETENV_KV 3\n:HEAD dummy\n:WRAP dummy\n";
    let result = FileEncContent::detect(kv_enc.to_string());
    assert!(result.is_err());
}

#[test]
fn test_decrypt_document_file() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    // Get public key from keystore first
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();

    // Load CryptoContext to get signing key
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);

    // Create file-enc content using signing key from CryptoContext
    let content = b"Hello, World!";
    let recipient_ids = vec![ALICE_MEMBER_ID.to_string()];
    let members = make_verified_members(std::slice::from_ref(&public_key));

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_ids,
        &members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: kid,
            signer_pub: public_key.clone(),
            debug: false,
        },
    )
    .unwrap();

    let encrypted_json = serde_json::to_string(&file_enc_doc).unwrap();
    let file_enc = FileEncContent::new_unchecked(encrypted_json);

    // Decrypt
    let decrypted = decrypt_document(&file_enc, ALICE_MEMBER_ID, &key_ctx, false).unwrap();
    assert_eq!(decrypted.as_ref() as &[u8], content);
}

#[test]
fn test_parse_verify_decrypt_file() {
    // Test that Verified types enforce verification before decryption
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    // Get public key from keystore first
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();

    // Load CryptoContext to get signing key
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);

    let content = b"Hello, Verified World!";
    let recipient_ids = vec![ALICE_MEMBER_ID.to_string()];
    let members = make_verified_members(std::slice::from_ref(&public_key));

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_ids,
        &members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: kid,
            signer_pub: public_key.clone(),
            debug: false,
        },
    )
    .unwrap();

    let encrypted_json = serde_json::to_string(&file_enc_doc).unwrap();

    // Use verify+decrypt API
    let file_doc: secretenv::model::file_enc::FileEncDocument =
        serde_json::from_str(&encrypted_json).unwrap();
    let workspace_path = temp_dir.path().join("workspace");
    let verified_file_doc = verify_file_document(&file_doc, Some(&workspace_path), false).unwrap();
    let decrypted = decrypt_file_document(
        &verified_file_doc,
        ALICE_MEMBER_ID,
        &key_ctx.kid,
        &key_ctx.private_key,
        false,
    )
    .unwrap();

    // Compare Zeroizing<Vec<u8>> with &[u8] using as_ref()
    assert_eq!(decrypted.as_ref() as &[u8], content);
}

#[test]
fn test_verify_file_document_returns_verified() {
    // Test that verify_file_document returns Verified<FileEncDocument>
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    // Get public key from keystore first
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();

    // Load CryptoContext to get signing key
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);

    let content = b"Test content";
    let recipient_ids = vec![ALICE_MEMBER_ID.to_string()];
    let members = make_verified_members(std::slice::from_ref(&public_key));

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_ids,
        &members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: kid,
            signer_pub: public_key.clone(),
            debug: false,
        },
    )
    .unwrap();

    // Verify document (returns Verified<FileEncDocument>)
    let workspace_path = temp_dir.path().join("workspace");
    let verified_doc = verify_file_document(&file_enc_doc, Some(&workspace_path), false).unwrap();

    // Check that we have verified proof information
    assert_eq!(verified_doc.proof().member_id, ALICE_MEMBER_ID);
    assert_eq!(verified_doc.proof().kid, kid.as_str());
}

// ---------------------------------------------------------------------------
// Error-path tests for decrypt_file_document
// ---------------------------------------------------------------------------

/// Helper: create an encrypted FileEncDocument + CryptoContext for error-path tests
/// The returned TempDir must be kept alive for the duration of the test
/// to prevent premature cleanup of keystore and workspace files.
fn create_encrypted_file_for_error_tests() -> (
    secretenv::model::file_enc::FileEncDocument,
    CryptoContext,
    String, // kid
    TempDir,
) {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap().clone();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, &kid).unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);

    let content = b"test content";
    let recipient_ids = vec![ALICE_MEMBER_ID.to_string()];
    let members = make_verified_members(std::slice::from_ref(&public_key));

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_ids,
        &members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: &kid,
            signer_pub: public_key.clone(),
            debug: false,
        },
    )
    .unwrap();

    (file_enc_doc, key_ctx, kid, temp_dir)
}

/// Helper: wrap a FileEncDocument into VerifiedFileEncDocument with a dummy proof
fn wrap_as_verified(
    doc: secretenv::model::file_enc::FileEncDocument,
    kid: &str,
) -> VerifiedFileEncDocument {
    let proof = SignatureVerificationProof::new(
        ALICE_MEMBER_ID.to_string(),
        kid.to_string(),
        VerifyingKeySource::SignerPubEmbedded,
        Vec::new(),
    );
    VerifiedFileEncDocument::new(doc, proof)
}

#[test]
fn test_decrypt_file_wrong_format() {
    let (mut doc, key_ctx, kid, _temp_dir) = create_encrypted_file_for_error_tests();

    // Tamper: set wrong format marker
    doc.protected.format = "secretenv.file@999".to_string();

    let verified = wrap_as_verified(doc, &kid);
    let result = decrypt_file_document(
        &verified,
        ALICE_MEMBER_ID,
        &key_ctx.kid,
        &key_ctx.private_key,
        false,
    );

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Invalid format"),
        "Expected 'Invalid format' in error, got: {err_msg}"
    );
}

#[test]
fn test_decrypt_file_wrong_payload_format() {
    let (mut doc, key_ctx, kid, _temp_dir) = create_encrypted_file_for_error_tests();

    // Tamper: set wrong payload format
    doc.protected.payload.protected.format = "secretenv.file.payload@999".to_string();

    let verified = wrap_as_verified(doc, &kid);
    let result = decrypt_file_document(
        &verified,
        ALICE_MEMBER_ID,
        &key_ctx.kid,
        &key_ctx.private_key,
        false,
    );

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Invalid payload format"),
        "Expected 'Invalid payload format' in error, got: {err_msg}"
    );
}

#[test]
fn test_decrypt_file_unsupported_aead() {
    let (mut doc, key_ctx, kid, _temp_dir) = create_encrypted_file_for_error_tests();

    // Tamper: set unsupported AEAD algorithm
    doc.protected.payload.protected.alg.aead = "aes-256-gcm".to_string();

    let verified = wrap_as_verified(doc, &kid);
    let result = decrypt_file_document(
        &verified,
        ALICE_MEMBER_ID,
        &key_ctx.kid,
        &key_ctx.private_key,
        false,
    );

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Unsupported AEAD algorithm"),
        "Expected 'Unsupported AEAD algorithm' in error, got: {err_msg}"
    );
}

#[test]
fn test_decrypt_file_sid_mismatch() {
    let (mut doc, key_ctx, kid, _temp_dir) = create_encrypted_file_for_error_tests();

    // Tamper: change payload SID so it mismatches the outer SID
    doc.protected.payload.protected.sid = uuid::Uuid::new_v4();

    let verified = wrap_as_verified(doc, &kid);
    let result = decrypt_file_document(
        &verified,
        ALICE_MEMBER_ID,
        &key_ctx.kid,
        &key_ctx.private_key,
        false,
    );

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("SID mismatch"),
        "Expected 'SID mismatch' in error, got: {err_msg}"
    );
}
