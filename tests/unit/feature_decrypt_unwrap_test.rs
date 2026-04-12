// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/decrypt/unwrap error paths
//!
//! Tests error cases and edge cases in decrypt/unwrap operations.
//! The happy path is covered by usecase_decrypt_test.rs; this file focuses on
//! error paths such as wrong kid, empty entries, and rid mismatch scenarios.

use crate::keygen_helpers::{
    make_decrypted_private_key_plaintext, make_recipient_key, make_verified_members,
};
use crate::test_utils::ALICE_MEMBER_ID;
use crate::test_utils::{setup_member_key_context, setup_test_keystore_from_fixtures};
use ed25519_dalek::SigningKey;
use secretenv::crypto::kem::decode_kem_secret_key;
use secretenv::crypto::types::keys::MasterKey;
use secretenv::feature::context::crypto::CryptoContext;
use secretenv::feature::decrypt::file::decrypt_file_document;
use secretenv::feature::encrypt::file::encrypt_file_document;
use secretenv::feature::envelope::binding::build_file_wrap_info;
use secretenv::feature::envelope::signature::SigningContext;
use secretenv::feature::envelope::unwrap::{unwrap_master_key, unwrap_master_key_for_file};
use secretenv::feature::envelope::wrap::build_wrap_item_for_file;
use secretenv::feature::key::protection::encryption::decrypt_private_key;
use secretenv::feature::kv::decrypt::decrypt_kv_document;
use secretenv::feature::kv::encrypt::encrypt_kv_document;
use secretenv::feature::verify::file::verify_file_document;
use secretenv::feature::verify::kv::signature::verify_kv_document;
use secretenv::format::kv::document::parse_kv_document;
use secretenv::format::kv::dotenv::parse_dotenv;
use secretenv::format::token::TokenCodec;
use secretenv::io::keystore::storage::{list_kids, load_private_key, load_public_key};
use secretenv::io::ssh::backend::signature_backend::SignatureBackend;
use secretenv::io::ssh::backend::ssh_keygen::SshKeygenBackend;
use secretenv::io::ssh::external::keygen::DefaultSshKeygen;
use secretenv::io::ssh::protocol::key_descriptor::SshKeyDescriptor;
use secretenv::model::file_enc::VerifiedFileEncDocument;
use secretenv::model::identifiers::jwk::{CRV_ED25519, CRV_X25519};
use secretenv::model::private_key::{IdentityKeysPrivate, JwkOkpPrivateKey, PrivateKeyPlaintext};
use secretenv::model::verification::{SignatureVerificationProof, VerifyingKeySource};
use tempfile::TempDir;
use uuid::Uuid;

// ============================================================================
// Helper Functions
// ============================================================================

/// Encrypt a file and return (verified_doc, key_ctx, kid, _temp_dir)
///
/// The returned TempDir must be kept alive for the duration of the test
/// to prevent premature cleanup of keystore and workspace files.
fn encrypt_file_for_test(
    content: &[u8],
) -> (
    secretenv::model::file_enc::VerifiedFileEncDocument,
    CryptoContext,
    String,
    TempDir,
) {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap().clone();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, &kid).unwrap();

    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);

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

    let verified_doc = verify_file_document(&file_enc_doc, false).unwrap();

    (verified_doc, key_ctx, kid, temp_dir)
}

/// Encrypt KV content and return (verified_doc, key_ctx, kid, _temp_dir)
///
/// The returned TempDir must be kept alive for the duration of the test
/// to prevent premature cleanup of keystore and workspace files.
fn encrypt_kv_for_test(
    dotenv_content: &str,
) -> (
    secretenv::model::kv_enc::verified::VerifiedKvEncDocument,
    CryptoContext,
    String,
    TempDir,
) {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap().clone();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, &kid).unwrap();

    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);

    let kv_map = parse_dotenv(dotenv_content).unwrap();
    let signer_pub = public_key.clone();
    let members = vec![public_key];
    let verified_members = make_verified_members(&members);

    let encrypted = encrypt_kv_document(
        &kv_map,
        &verified_members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: &kid,
            signer_pub,
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap();

    let doc = parse_kv_document(&encrypted).unwrap();
    let verified_doc = verify_kv_document(&doc, false).unwrap();

    (verified_doc, key_ctx, kid, temp_dir)
}

// ============================================================================
// Test: find_wrap_item_by_kid (tested indirectly through public APIs)
// ============================================================================

/// Test that decryption succeeds when the correct kid is used (find_wrap_item_by_kid success path).
#[test]
fn test_find_wrap_item_by_kid() {
    let (verified_doc, key_ctx, kid, _temp_dir) = encrypt_file_for_test(b"test content");

    // Decryption with correct kid should succeed
    let result = decrypt_file_document(
        &verified_doc,
        ALICE_MEMBER_ID,
        &kid,
        &key_ctx.private_key,
        false,
    );

    assert!(result.is_ok());
    assert_eq!(result.unwrap().as_ref() as &[u8], b"test content");
}

/// Test that a non-existent kid produces an error containing "No wrap found".
#[test]
fn test_find_wrap_item_by_kid_not_found() {
    let (verified_doc, key_ctx, _kid, _temp_dir) = encrypt_file_for_test(b"test content");

    let nonexistent_kid = "00000000000000000000000000";
    let result = decrypt_file_document(
        &verified_doc,
        ALICE_MEMBER_ID,
        nonexistent_kid,
        &key_ctx.private_key,
        false,
    );

    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("No wrap found"),
        "Error should mention 'No wrap found', got: {}",
        err_msg
    );
}

/// Test that kid matches but rid doesn't match member_id -- decryption fails.
#[test]
fn test_find_wrap_item_by_kid_rid_mismatch_fails() {
    let (verified_doc, key_ctx, kid, _temp_dir) = encrypt_file_for_test(b"rid mismatch test");

    // Use a different member_id (not matching rid in wrap item) but correct kid and private key.
    let different_member_id = "different@example.com";
    let result = decrypt_file_document(
        &verified_doc,
        different_member_id,
        &kid,
        &key_ctx.private_key,
        false,
    );

    assert!(
        result.is_err(),
        "Decryption should fail when member_id doesn't match rid"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("does not match member_id"),
        "Error should mention rid mismatch, got: {}",
        err_msg
    );
    assert!(
        err_msg.contains(different_member_id),
        "Error should mention requested member_id '{}', got: {}",
        different_member_id,
        err_msg
    );
}

// ============================================================================
// Test: decrypt file/kv document roundtrips
// ============================================================================

/// Test encrypt then decrypt file-enc roundtrip matches original content.
#[test]
fn test_decrypt_file_document_roundtrip() {
    let original_content = b"Hello, World! This is a file encryption roundtrip test.";
    let (verified_doc, key_ctx, kid, _temp_dir) = encrypt_file_for_test(original_content);

    let decrypted = decrypt_file_document(
        &verified_doc,
        ALICE_MEMBER_ID,
        &kid,
        &key_ctx.private_key,
        false,
    )
    .unwrap();

    assert_eq!(
        decrypted.as_ref() as &[u8],
        original_content,
        "Decrypted content should match original"
    );
}

/// Test encrypt then decrypt kv-enc roundtrip matches original key-value pairs.
#[test]
fn test_decrypt_kv_document_roundtrip() {
    let dotenv = "SECRET_KEY=my-secret-value\n";
    let (verified_doc, key_ctx, kid, _temp_dir) = encrypt_kv_for_test(dotenv);

    let decrypted = decrypt_kv_document(
        &verified_doc,
        ALICE_MEMBER_ID,
        &kid,
        &key_ctx.private_key,
        false,
    )
    .unwrap();

    assert_eq!(decrypted.len(), 1);
    let value = decrypted
        .get("SECRET_KEY")
        .expect("SECRET_KEY should exist");
    assert_eq!(
        String::from_utf8(value.to_vec()).unwrap(),
        "my-secret-value"
    );
}

/// Test that kv decryption fails when the located wrap's rid does not match member_id.
#[test]
fn test_decrypt_kv_document_rid_mismatch_fails() {
    let dotenv = "SECRET_KEY=my-secret-value\n";
    let (verified_doc, key_ctx, kid, _temp_dir) = encrypt_kv_for_test(dotenv);

    let different_member_id = "different@example.com";
    let result = decrypt_kv_document(
        &verified_doc,
        different_member_id,
        &kid,
        &key_ctx.private_key,
        false,
    );

    assert!(
        result.is_err(),
        "KV decryption should fail when member_id doesn't match rid"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("does not match member_id"),
        "Error should mention rid mismatch, got: {}",
        err_msg
    );
    assert!(
        err_msg.contains(different_member_id),
        "Error should mention requested member_id '{}', got: {}",
        different_member_id,
        err_msg
    );
}

// ============================================================================
// Test: decrypt_kv_entries edge cases (tested through decrypt_kv_document)
// ============================================================================

/// Test that encrypting an empty KV map produces an empty decrypted map.
#[test]
fn test_decrypt_kv_entries_empty() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap().clone();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, &kid).unwrap();

    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);

    // Create empty KV map
    let kv_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let signer_pub = public_key.clone();
    let members = vec![public_key];
    let verified_members = make_verified_members(&members);

    let encrypted = encrypt_kv_document(
        &kv_map,
        &verified_members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: &kid,
            signer_pub,
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap();

    let doc = parse_kv_document(&encrypted).unwrap();
    let verified_doc = verify_kv_document(&doc, false).unwrap();

    let decrypted = decrypt_kv_document(
        &verified_doc,
        ALICE_MEMBER_ID,
        &kid,
        &key_ctx.private_key,
        false,
    )
    .unwrap();

    assert!(
        decrypted.is_empty(),
        "Decrypting empty entries should produce empty map"
    );
}

/// Test that multiple KV entries are all decrypted correctly.
#[test]
fn test_decrypt_kv_entries_multiple() {
    let dotenv = "DB_HOST=localhost\nDB_PORT=5432\nDB_USER=admin\nDB_PASS=secret\n";
    let (verified_doc, key_ctx, kid, _temp_dir) = encrypt_kv_for_test(dotenv);

    let decrypted = decrypt_kv_document(
        &verified_doc,
        ALICE_MEMBER_ID,
        &kid,
        &key_ctx.private_key,
        false,
    )
    .unwrap();

    assert_eq!(decrypted.len(), 4, "Should have 4 decrypted entries");

    let expected = [
        ("DB_HOST", "localhost"),
        ("DB_PORT", "5432"),
        ("DB_USER", "admin"),
        ("DB_PASS", "secret"),
    ];

    for (key, expected_value) in &expected {
        let value = decrypted
            .get(*key)
            .unwrap_or_else(|| panic!("{} should exist in decrypted map", key));
        assert_eq!(
            String::from_utf8(value.to_vec()).unwrap(),
            *expected_value,
            "Value for {} should match",
            key
        );
    }
}

// ============================================================================
// Test: unwrap_master_key_for_file error path
// ============================================================================

/// Test that using a wrong kid for file decryption produces an error.
#[test]
fn test_unwrap_master_key_for_file_wrong_kid() {
    let (verified_doc, key_ctx, _kid, _temp_dir) = encrypt_file_for_test(b"wrong kid test");

    // Use a completely different kid that doesn't exist in the wrap items
    let wrong_kid = "AAAAAAAAAAAAAAAAAAAAAAAAAA";
    let result = decrypt_file_document(
        &verified_doc,
        ALICE_MEMBER_ID,
        wrong_kid,
        &key_ctx.private_key,
        false,
    );

    assert!(result.is_err(), "Decryption with wrong kid should fail");
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("No wrap found"),
        "Error should mention 'No wrap found', got: {}",
        err_msg
    );
    assert!(
        err_msg.contains(wrong_kid),
        "Error should mention the requested kid '{}', got: {}",
        wrong_kid,
        err_msg
    );
}

// ============================================================================
// Tests merged from services_enc_unwrap_test.rs
// ============================================================================

/// Generate Ed25519 signing key from seed for tests
fn generate_ed25519_keypair(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

fn create_test_master_key() -> MasterKey {
    let key_bytes = [1u8; 32];
    MasterKey::new(key_bytes)
}

#[test]
fn test_unwrap_master_key_for_file() {
    // Setup test keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();
    let encrypted_private_key = load_private_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();

    // Decrypt private key
    let ssh_pub =
        std::fs::read_to_string(temp_dir.path().join(".ssh").join("test_ed25519.pub")).unwrap();
    let backend: Box<dyn SignatureBackend> = Box::new(SshKeygenBackend::new(
        Box::new(DefaultSshKeygen::new("ssh-keygen")),
        SshKeyDescriptor::from_path(temp_dir.path().join(".ssh").join("test_ed25519")),
    ));
    let private_key =
        decrypt_private_key(&encrypted_private_key, backend.as_ref(), &ssh_pub, false).unwrap();

    let signing_key = generate_ed25519_keypair([2u8; 32]);
    let content = b"Hello, World!";
    let recipient_ids = vec![ALICE_MEMBER_ID.to_string()];
    let members = make_verified_members(std::slice::from_ref(&public_key));

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_ids,
        &members,
        &SigningContext {
            signing_key: &signing_key,
            signer_kid: kid,
            signer_pub: public_key.clone(),
            debug: false,
        },
    )
    .unwrap();

    // Wrap private key in Decrypted for unwrap API
    let decrypted_key =
        make_decrypted_private_key_plaintext(&private_key, ALICE_MEMBER_ID, kid, "SHA256:test");

    // Wrap in VerifiedFileEncDocument (tests use freshly encrypted content, treated as verified)
    let proof = SignatureVerificationProof::new(
        ALICE_MEMBER_ID.to_string(),
        kid.to_string(),
        VerifyingKeySource::SignerPubEmbedded,
        Vec::new(),
    );
    let verified = VerifiedFileEncDocument::new(file_enc_doc, proof);

    // Unwrap master key
    let unwrapped_key =
        unwrap_master_key_for_file(&verified, ALICE_MEMBER_ID, kid, &decrypted_key, false).unwrap();

    // Verify unwrapped key is valid
    assert_eq!(unwrapped_key.as_bytes().len(), 32);
}

#[test]
fn test_unwrap_master_key_for_file_wrong_member() {
    // Setup test keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();

    let signing_key = generate_ed25519_keypair([2u8; 32]);
    let content = b"Hello, World!";
    let recipient_ids = vec![ALICE_MEMBER_ID.to_string()];
    let members = make_verified_members(std::slice::from_ref(&public_key));

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_ids,
        &members,
        &SigningContext {
            signing_key: &signing_key,
            signer_kid: kid,
            signer_pub: public_key.clone(),
            debug: false,
        },
    )
    .unwrap();

    let proof = SignatureVerificationProof::new(
        ALICE_MEMBER_ID.to_string(),
        kid.to_string(),
        VerifyingKeySource::SignerPubEmbedded,
        Vec::new(),
    );
    let verified = VerifiedFileEncDocument::new(file_enc_doc, proof);

    // Try to unwrap with wrong member (should fail - bob doesn't have a wrap)
    let dummy_private_key = make_decrypted_private_key_plaintext(
        &PrivateKeyPlaintext {
            keys: IdentityKeysPrivate {
                kem: JwkOkpPrivateKey {
                    kty: "OKP".to_string(),
                    crv: CRV_X25519.to_string(),
                    x: "dummy".to_string(),
                    d: "dummy".to_string(),
                },
                sig: JwkOkpPrivateKey {
                    kty: "OKP".to_string(),
                    crv: CRV_ED25519.to_string(),
                    x: "dummy".to_string(),
                    d: "dummy".to_string(),
                },
            },
        },
        "bob@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GJ",
        "SHA256:test",
    );

    let result = unwrap_master_key_for_file(
        &verified,
        "bob@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GJ", // Different kid (should fail)
        &dummy_private_key,
        false,
    );
    assert!(result.is_err());
}

#[test]
fn test_unwrap_master_key_from_wrap_item() {
    // Setup test keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();
    let encrypted_private_key = load_private_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();

    // Decrypt private key first (we'll need it for unwrap)
    let ssh_pub =
        std::fs::read_to_string(temp_dir.path().join(".ssh").join("test_ed25519.pub")).unwrap();
    let backend: Box<dyn SignatureBackend> = Box::new(SshKeygenBackend::new(
        Box::new(DefaultSshKeygen::new("ssh-keygen")),
        SshKeyDescriptor::from_path(temp_dir.path().join(".ssh").join("test_ed25519")),
    ));
    let private_key_plaintext =
        decrypt_private_key(&encrypted_private_key, backend.as_ref(), &ssh_pub, false).unwrap();

    let sid = Uuid::new_v4();
    let master_key = create_test_master_key();

    // Extract kid from public key for kids list
    // Create wrap item (wrap in Attested for API)
    let attested_pubkey = make_recipient_key(public_key.clone());
    let wrap_item = build_wrap_item_for_file(&attested_pubkey, &sid, &master_key, false).unwrap();

    // Unwrap master key using the same private key that matches the public key used to create wrap
    // Note: build_wrap_item_for_file uses hpke_info::file, so we need to use unwrap_master_key_base
    // with hpke_info::file instead of unwrap_master_key_from_wrap_item (which uses hpke_info::kv_file)
    let decrypted_key = make_decrypted_private_key_plaintext(
        &private_key_plaintext,
        ALICE_MEMBER_ID,
        &public_key.protected.kid,
        "SHA256:test",
    );
    let kem_secret_key = decode_kem_secret_key(&decrypted_key).unwrap();
    let unwrapped_key = unwrap_master_key(
        &wrap_item,
        &sid,
        &kem_secret_key,
        build_file_wrap_info,
        false,
        "test_unwrap_master_key_from_wrap_item",
    )
    .unwrap();

    // Verify unwrapped key matches original
    assert_eq!(unwrapped_key.as_bytes(), master_key.as_bytes());
}

/// Test defence-in-depth: HPKE AAD binding (aad=info) prevents unwrap with wrong AAD
#[test]
fn test_hpke_aad_binding_defence_in_depth() {
    // Setup test keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();
    let encrypted_private_key = load_private_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();

    // Decrypt private key
    let ssh_pub =
        std::fs::read_to_string(temp_dir.path().join(".ssh").join("test_ed25519.pub")).unwrap();
    let backend: Box<dyn SignatureBackend> = Box::new(SshKeygenBackend::new(
        Box::new(DefaultSshKeygen::new("ssh-keygen")),
        SshKeyDescriptor::from_path(temp_dir.path().join(".ssh").join("test_ed25519")),
    ));
    let private_key_plaintext =
        decrypt_private_key(&encrypted_private_key, backend.as_ref(), &ssh_pub, false).unwrap();

    let sid = Uuid::new_v4();
    let master_key = create_test_master_key();

    // Create wrap item (uses aad=info) - wrap in Attested for API
    let attested_pubkey = make_recipient_key(public_key.clone());
    let wrap_item = build_wrap_item_for_file(&attested_pubkey, &sid, &master_key, false).unwrap();

    // Try to unwrap with empty AAD (old behavior) - should fail
    // This demonstrates that aad=info binding is enforced
    let decrypted_key = make_decrypted_private_key_plaintext(
        &private_key_plaintext,
        ALICE_MEMBER_ID,
        &public_key.protected.kid,
        "SHA256:test",
    );
    let kem_secret_key = decode_kem_secret_key(&decrypted_key).unwrap();

    // Attempt unwrap with wrong AAD (empty instead of info)
    // This should fail because the wrap was created with aad=info
    use secretenv::crypto::kem::open_base;
    use secretenv::crypto::types::data::{Aad, Ciphertext, Enc};
    use secretenv::support::codec::base64_public::decode_base64url_nopad;

    let enc_bytes = decode_base64url_nopad(&wrap_item.enc, "enc").unwrap();
    let enc = Enc::from(enc_bytes);
    let ct_bytes = decode_base64url_nopad(&wrap_item.ct, "ct").unwrap();
    let ct = Ciphertext::from(ct_bytes);

    let info = build_file_wrap_info(&sid, kid).unwrap();
    let wrong_aad = Aad::empty(); // Wrong AAD (empty instead of info)

    let result = open_base(&kem_secret_key, &enc, &info, &wrong_aad, &ct);

    // Should fail because AAD doesn't match (defence-in-depth)
    assert!(
        result.is_err(),
        "Unwrap with wrong AAD (empty instead of info) should fail"
    );
}
