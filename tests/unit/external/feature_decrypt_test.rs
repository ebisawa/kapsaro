// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/decrypt module
//!
//! Tests for file-enc decryption.

use crate::keygen_helpers::build_verified_recipient_keys;
use crate::test_utils::ALICE_MEMBER_HANDLE;
use crate::test_utils::{
    setup_member_key_context, setup_test_keystore_from_fixtures,
    update_active_private_key_expires_at,
};
use secretenv_core::cli_api::test_support::domain::file_enc::VerifiedFileEncDocument;
use secretenv_core::cli_api::test_support::domain::verification::{
    SignatureVerificationProof, VerifyingKeySource,
};
use secretenv_core::cli_api::test_support::operations::context::crypto::CryptoContext;
use secretenv_core::cli_api::test_support::operations::decrypt::file::{
    decrypt_file_document, decrypt_file_document_with_context,
};
use secretenv_core::cli_api::test_support::operations::encrypt::file::encrypt_file_document;
use secretenv_core::cli_api::test_support::operations::envelope::signature::SigningContext;
use secretenv_core::cli_api::test_support::operations::verify::file::{
    verify_file_content, verify_file_document,
};
use secretenv_core::cli_api::test_support::storage::keystore::storage::{
    list_kids, load_public_key,
};
use secretenv_core::cli_api::test_support::wire::content::FileEncContent;
use tempfile::TempDir;

#[test]
fn test_file_enc_content_detect_accepts_file_enc() {
    // Create file-enc content
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    // Get public key from keystore first
    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, kid).unwrap();

    // Load CryptoContext to get signing key
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);

    let content = b"Hello, World!";
    let recipient_handles = vec![ALICE_MEMBER_HANDLE.to_string()];
    let members = build_verified_recipient_keys(std::slice::from_ref(&public_key));

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_handles,
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
fn test_file_enc_content_detect_rejects_kv_enc() {
    // kv-enc format should be rejected by FileEncContent::detect
    let kv_enc = ":SECRETENV_KV 6\n:HEAD dummy\n:WRAP dummy\n";
    let result = FileEncContent::detect(kv_enc.to_string());
    assert!(result.is_err());
}

#[test]
fn test_verify_content_then_decrypt_file() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    // Get public key from keystore first
    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, kid).unwrap();

    // Load CryptoContext to get signing key
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);

    // Create file-enc content using signing key from CryptoContext
    let content = b"Hello, World!";
    let recipient_handles = vec![ALICE_MEMBER_HANDLE.to_string()];
    let members = build_verified_recipient_keys(std::slice::from_ref(&public_key));

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_handles,
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

    let verified = verify_file_content(&file_enc, false).unwrap();
    let decrypted = decrypt_file_document(
        &verified,
        ALICE_MEMBER_HANDLE,
        &key_ctx.kid,
        &key_ctx.private_key,
        false,
    )
    .unwrap();
    assert_eq!(decrypted.as_ref() as &[u8], content);
}

#[test]
fn test_parse_verify_decrypt_file() {
    // Test that Verified types enforce verification before decryption
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    // Get public key from keystore first
    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, kid).unwrap();

    // Load CryptoContext to get signing key
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);

    let content = b"Hello, Verified World!";
    let recipient_handles = vec![ALICE_MEMBER_HANDLE.to_string()];
    let members = build_verified_recipient_keys(std::slice::from_ref(&public_key));

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_handles,
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
    let file_doc: secretenv_core::cli_api::test_support::domain::file_enc::FileEncDocument =
        serde_json::from_str(&encrypted_json).unwrap();
    let verified_file_doc = verify_file_document(&file_doc, false).unwrap();
    let decrypted = decrypt_file_document(
        &verified_file_doc,
        ALICE_MEMBER_HANDLE,
        &key_ctx.kid,
        &key_ctx.private_key,
        false,
    )
    .unwrap();

    // Compare Zeroizing<Vec<u8>> with &[u8] using as_ref()
    assert_eq!(decrypted.as_ref() as &[u8], content);
}

#[test]
fn test_decrypt_file_with_context_falls_back_to_old_local_key() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let old_key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    let old_kid = old_key_ctx.kid.to_string();
    let old_public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &old_kid).unwrap();

    let content = b"Hello from the old key";
    let recipient_handles = vec![ALICE_MEMBER_HANDLE.to_string()];
    let members = build_verified_recipient_keys(std::slice::from_ref(&old_public_key));
    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_handles,
        &members,
        &SigningContext {
            signing_key: &old_key_ctx.signing_key,
            signer_kid: &old_kid,
            signer_pub: old_public_key,
            debug: false,
        },
    )
    .unwrap();

    update_active_private_key_expires_at(
        temp_dir.path(),
        ALICE_MEMBER_HANDLE,
        "2028-01-01T00:00:00Z",
    );
    let new_key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    assert_ne!(new_key_ctx.kid.to_string(), old_kid);

    let encrypted_json = serde_json::to_string(&file_enc_doc).unwrap();
    let verified =
        verify_file_content(&FileEncContent::new_unchecked(encrypted_json), false).unwrap();
    let decrypted =
        decrypt_file_document_with_context(&verified, ALICE_MEMBER_HANDLE, &new_key_ctx, false)
            .unwrap();

    assert_eq!(decrypted.value.as_ref() as &[u8], content);
    assert_eq!(decrypted.key_info.kid, old_kid);
    assert!(decrypted.key_info.used_fallback);
}

#[test]
fn test_verify_file_document_returns_verified() {
    // Test that verify_file_document returns Verified<FileEncDocument>
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    // Get public key from keystore first
    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, kid).unwrap();

    // Load CryptoContext to get signing key
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);

    let content = b"Test content";
    let recipient_handles = vec![ALICE_MEMBER_HANDLE.to_string()];
    let members = build_verified_recipient_keys(std::slice::from_ref(&public_key));

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_handles,
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
    let verified_doc = verify_file_document(&file_enc_doc, false).unwrap();

    // Check that we have verified proof information
    assert_eq!(verified_doc.proof().member_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(verified_doc.proof().kid, kid.as_str());
}

// ---------------------------------------------------------------------------
// Error-path tests for decrypt_file_document
// ---------------------------------------------------------------------------

/// Helper: create an encrypted FileEncDocument + CryptoContext for error-path tests
/// The returned TempDir must be kept alive for the duration of the test
/// to prevent premature cleanup of keystore and workspace files.
fn build_encrypted_file_for_error_tests() -> (
    secretenv_core::cli_api::test_support::domain::file_enc::FileEncDocument,
    CryptoContext,
    String, // kid
    TempDir,
) {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap().clone();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &kid).unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);

    let content = b"test content";
    let recipient_handles = vec![ALICE_MEMBER_HANDLE.to_string()];
    let members = build_verified_recipient_keys(std::slice::from_ref(&public_key));

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_handles,
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
    doc: secretenv_core::cli_api::test_support::domain::file_enc::FileEncDocument,
    kid: &str,
) -> VerifiedFileEncDocument {
    let proof = SignatureVerificationProof::new(
        ALICE_MEMBER_HANDLE.to_string(),
        kid.to_string(),
        VerifyingKeySource::SignerPubEmbedded,
        Vec::new(),
    );
    VerifiedFileEncDocument::new(doc, proof)
}

#[test]
fn test_decrypt_file_wrong_format() {
    let (mut doc, key_ctx, kid, _temp_dir) = build_encrypted_file_for_error_tests();

    // Tamper: set wrong format marker
    doc.protected.format = "secretenv.file@999".to_string();

    let verified = wrap_as_verified(doc, &kid);
    let result = decrypt_file_document(
        &verified,
        ALICE_MEMBER_HANDLE,
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
    let (mut doc, key_ctx, kid, _temp_dir) = build_encrypted_file_for_error_tests();

    // Tamper: set wrong payload format
    doc.protected.payload.protected.format = "secretenv.file.payload@999".to_string();

    let verified = wrap_as_verified(doc, &kid);
    let result = decrypt_file_document(
        &verified,
        ALICE_MEMBER_HANDLE,
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
    let (mut doc, key_ctx, kid, _temp_dir) = build_encrypted_file_for_error_tests();

    // Tamper: set unsupported AEAD algorithm
    doc.protected.payload.protected.alg.aead = "aes-256-gcm".to_string();

    let verified = wrap_as_verified(doc, &kid);
    let result = decrypt_file_document(
        &verified,
        ALICE_MEMBER_HANDLE,
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
    let (mut doc, key_ctx, kid, _temp_dir) = build_encrypted_file_for_error_tests();

    // Tamper: change payload SID so it mismatches the outer SID
    doc.protected.payload.protected.sid = uuid::Uuid::new_v4();

    let verified = wrap_as_verified(doc, &kid);
    let result = decrypt_file_document(
        &verified,
        ALICE_MEMBER_HANDLE,
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
