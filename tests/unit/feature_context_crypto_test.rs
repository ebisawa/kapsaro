// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for core/usecase/common module
//!
//! Tests for common decryption helpers and member key context.

use crate::app::context::crypto::load_crypto_context;
use crate::test_utils::keygen_helpers::build_verified_recipient_keys;
use crate::test_utils::{
    load_fixture_ssh_pubkey, setup_member_key_context, setup_test_keystore_from_fixtures,
};
use secretenv::feature::decrypt::file::decrypt_file_document;
use secretenv::feature::encrypt::file::encrypt_file_document;
use secretenv::feature::envelope::signature::SigningContext;
use secretenv::feature::kv::decrypt::decrypt_kv_document;
use secretenv::feature::kv::encrypt::encrypt_kv_document;
use secretenv::feature::verify::file::verify_file_document;
use secretenv::feature::verify::kv::signature::verify_kv_document;
use secretenv::format::kv::document::parse_kv_document;
use secretenv::format::kv::dotenv::parse_dotenv;
use secretenv::format::token::TokenCodec;
use secretenv::io::keystore::storage::{list_kids, load_public_key, save_key_pair_atomic};
use secretenv::model::public_key::PublicKey;
use std::fs;

const ALICE_MEMBER_ID: &str = "alice@example.com";

#[test]
fn test_parse_verify_decrypt_kv() {
    // Setup test keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    // Load CryptoContext (use active key) - this gives us the signing key
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);

    // Get public key from keystore
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();

    // Create kv-enc content using signing key from CryptoContext
    let kv_map = parse_dotenv("DATABASE_URL=postgres://localhost\nAPI_KEY=secret123\n").unwrap();
    let members = vec![public_key.clone()];
    let verified_members = build_verified_recipient_keys(&members);

    let encrypted = encrypt_kv_document(
        &kv_map,
        &verified_members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: kid,
            signer_pub: public_key,
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap();

    // Verify and decrypt
    let doc = parse_kv_document(&encrypted).unwrap();
    let verified_doc = verify_kv_document(&doc, false).unwrap();
    let decrypted = decrypt_kv_document(
        &verified_doc,
        ALICE_MEMBER_ID,
        &key_ctx.kid,
        &key_ctx.private_key,
        false,
    )
    .unwrap();

    // Verify decrypted content (convert Zeroizing<Vec<u8>> to String for comparison)
    let db_url = decrypted
        .get("DATABASE_URL")
        .map(|v| String::from_utf8(v.to_vec()).unwrap());
    let api_key = decrypted
        .get("API_KEY")
        .map(|v| String::from_utf8(v.to_vec()).unwrap());
    assert_eq!(db_url, Some("postgres://localhost".to_string()));
    assert_eq!(api_key, Some("secret123".to_string()));
}

#[test]
fn test_parse_verify_decrypt_file() {
    // Setup test keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    // Load CryptoContext (use active key) - this gives us the signing key
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);

    // Get public key from keystore
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();

    // Create file-enc content using signing key from CryptoContext
    let content = b"Hello, World!";
    let recipient_ids = vec![ALICE_MEMBER_ID.to_string()];
    let members = vec![public_key.clone()];
    let verified_members = build_verified_recipient_keys(&members);

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_ids,
        &verified_members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: kid,
            signer_pub: public_key,
            debug: false,
        },
    )
    .unwrap();

    let encrypted_json = serde_json::to_string(&file_enc_doc).unwrap();

    // Verify and decrypt
    let doc: secretenv::model::file_enc::FileEncDocument =
        serde_json::from_str(&encrypted_json).unwrap();
    let verified_doc = verify_file_document(&doc, false).unwrap();
    let decrypted = decrypt_file_document(
        &verified_doc,
        ALICE_MEMBER_ID,
        &key_ctx.kid,
        &key_ctx.private_key,
        false,
    )
    .unwrap();

    // Verify decrypted content (compare Zeroizing<Vec<u8>> with &[u8] using as_ref())
    assert_eq!(decrypted.as_ref() as &[u8], content);
}

#[test]
fn test_crypto_context_load() {
    // Setup test keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    // Get kid from keystore
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();

    // Load CryptoContext
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));

    // Verify context
    assert_eq!(key_ctx.member_id, ALICE_MEMBER_ID);
    assert_eq!(key_ctx.kid, *kid);
    // Verify pub_key_source works by loading the signer's public key
    let loaded = key_ctx.pub_key_source.load_public_key(ALICE_MEMBER_ID);
    assert!(loaded.is_ok());
}

#[test]
fn test_crypto_context_load_without_explicit_kid() {
    // Setup test keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);

    // Load CryptoContext without explicit kid (should use active key)
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);

    // Verify context
    assert_eq!(key_ctx.member_id, ALICE_MEMBER_ID);
    assert!(!key_ctx.kid.is_empty());
    // Verify pub_key_source works by loading the signer's public key
    let loaded = key_ctx.pub_key_source.load_public_key(ALICE_MEMBER_ID);
    assert!(loaded.is_ok());
}

#[test]
fn test_crypto_context_load_fails_when_public_key_mismatches_private_key() {
    // Setup test keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    // Ensure there are at least two valid key directories by creating one more.
    let ssh_priv = temp_dir.path().join(".ssh").join("test_ed25519");
    let ssh_pub = load_fixture_ssh_pubkey();
    let (plaintext2, public_key2) =
        crate::test_utils::keygen_helpers::keygen_test(ALICE_MEMBER_ID, &ssh_priv, &ssh_pub)
            .unwrap();
    let private_key2 = crate::test_utils::keygen_helpers::build_test_private_key(
        &plaintext2,
        &public_key2.protected.member_id,
        &public_key2.protected.kid,
        &ssh_priv,
        &ssh_pub,
    )
    .unwrap();
    save_key_pair_atomic(
        &keystore_root,
        &public_key2.protected.member_id,
        &public_key2.protected.kid,
        &private_key2,
        &public_key2,
    )
    .unwrap();

    // Get two kids
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    assert!(kids.len() >= 2);
    let kid1 = kids[0].clone();
    let kid2 = kids[1].clone();
    assert_ne!(kid1, kid2);

    // Overwrite kid1's public.json with kid2's PublicKey (still valid), creating mismatch.
    let public2: PublicKey = load_public_key(&keystore_root, ALICE_MEMBER_ID, &kid2).unwrap();
    let kid1_public_path = keystore_root
        .join(ALICE_MEMBER_ID)
        .join(&kid1)
        .join("public.json");
    fs::write(
        &kid1_public_path,
        serde_json::to_string_pretty(&public2).unwrap(),
    )
    .unwrap();

    // Now loading CryptoContext for kid1 should fail due to mismatch.
    let ssh_pub_for_kdf = fs::read_to_string(temp_dir.path().join(".ssh").join("test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let backend: Box<dyn secretenv::io::ssh::backend::SignatureBackend> =
        Box::new(crate::test_utils::ed25519_backend::Ed25519DirectBackend::new(&ssh_priv).unwrap());

    let result = load_crypto_context(
        ALICE_MEMBER_ID,
        backend,
        ssh_pub_for_kdf,
        Some(&kid1),
        Some(&keystore_root),
        Some(temp_dir.path().join("workspace")),
        false,
    );
    assert!(result.is_err());
    let msg = format!("{}", result.err().unwrap());
    assert!(msg.contains("V-PRIVATEKEY-PUBKEY-MISMATCH") || msg.contains("mismatch"));
}
