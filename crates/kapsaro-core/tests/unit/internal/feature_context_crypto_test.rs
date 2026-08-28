// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for core/usecase/common module
//!
//! Tests for common decryption helpers and member key context.

use crate::app::context::crypto::load_crypto_context_with_access;
use crate::cli_api::test_support::storage::keystore::storage::{
    list_kids, load_public_key, save_key_pair_atomic,
};
use crate::feature::context::crypto::{build_signing_context, SigningContext};
use crate::feature::decrypt::file::decrypt_file_document_with_context;
use crate::feature::encrypt::file::encrypt_file_document;
use crate::feature::kv::decrypt::decrypt_kv_document_with_context;
use crate::feature::kv::encrypt::encrypt_kv_map_with_wrap_mutation;
use crate::feature::verify::file::verify_file_document;
use crate::feature::verify::kv::signature::verify_kv_document;
use crate::format::kv::document::parse_kv_document;
use crate::format::kv::dotenv::parse_dotenv;
use crate::format::token::TokenCodec;
use crate::io::keystore::access::KeystoreAccess;
use crate::model::identity::MemberHandle;
use crate::test_utils::keygen_helpers::build_verified_recipient_keys;
use crate::test_utils::{
    load_fixture_ssh_pubkey, setup_member_key_context, setup_test_keystore_from_fixtures,
};
use std::fs;

const ALICE_MEMBER_HANDLE: &str = "alice@example.com";

#[test]
fn test_parse_verify_decrypt_kv() {
    // Setup test keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    // Load CryptoContext (use active key) - this gives us the signing key
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);

    // Get public key from keystore
    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, kid).unwrap();

    // Create kv-enc content using signing key from CryptoContext
    let kv_map = parse_dotenv("DATABASE_URL=postgres://localhost\nAPI_KEY=secret123\n").unwrap();
    let members = vec![public_key.clone()];
    let verified_members = build_verified_recipient_keys(&members);

    let encrypted = encrypt_kv_map_with_wrap_mutation(
        &kv_map,
        &verified_members,
        &SigningContext {
            signing_key: key_ctx.signing_key(),
            signer_kid: kid,
            signer_pub: public_key,
        },
        TokenCodec::JsonJcs,
        false,
        |_| Ok(()),
    )
    .unwrap();

    // Verify and decrypt
    let doc = parse_kv_document(&encrypted).unwrap();
    let verified_doc = verify_kv_document(&doc).unwrap();
    let decrypted =
        decrypt_kv_document_with_context(&verified_doc, ALICE_MEMBER_HANDLE, &key_ctx).unwrap();

    // Verify decrypted content (convert Zeroizing<Vec<u8>> to String for comparison)
    let db_url = decrypted
        .value
        .get("DATABASE_URL")
        .map(|v| String::from_utf8(v.to_vec()).unwrap());
    let api_key = decrypted
        .value
        .get("API_KEY")
        .map(|v| String::from_utf8(v.to_vec()).unwrap());
    assert_eq!(db_url, Some("postgres://localhost".to_string()));
    assert_eq!(api_key, Some("secret123".to_string()));
}

#[test]
fn test_parse_verify_decrypt_file() {
    // Setup test keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    // Load CryptoContext (use active key) - this gives us the signing key
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);

    // Get public key from keystore
    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, kid).unwrap();

    // Create file-enc content using signing key from CryptoContext
    let content = b"Hello, World!";
    let recipient_handles = vec![ALICE_MEMBER_HANDLE.to_string()];
    let members = vec![public_key.clone()];
    let verified_members = build_verified_recipient_keys(&members);

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_handles,
        &verified_members,
        &SigningContext {
            signing_key: key_ctx.signing_key(),
            signer_kid: kid,
            signer_pub: public_key,
        },
    )
    .unwrap();

    let encrypted_json = serde_json::to_string(&file_enc_doc).unwrap();

    // Verify and decrypt
    let doc: crate::model::file_enc::FileEncDocument =
        serde_json::from_str(&encrypted_json).unwrap();
    let verified_doc = verify_file_document(&doc).unwrap();
    let decrypted =
        decrypt_file_document_with_context(&verified_doc, ALICE_MEMBER_HANDLE, &key_ctx).unwrap();

    // Verify decrypted content (compare Zeroizing<Vec<u8>> with &[u8] using as_ref())
    assert_eq!(decrypted.value.as_ref() as &[u8], content);
}

#[test]
fn test_crypto_context_load() {
    // Setup test keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    // Get kid from keystore
    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();

    // Load CryptoContext
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));

    // Verify context
    assert_eq!(key_ctx.member_handle(), ALICE_MEMBER_HANDLE);
    assert_eq!(key_ctx.kid(), kid.as_str());
    // Verify pub_key_source works by loading the signer's public key
    let loaded = key_ctx
        .pub_key_source
        .load_public_key(key_ctx.member_handle_id());
    assert!(loaded.is_ok());
}

#[test]
fn test_crypto_context_load_without_explicit_kid() {
    // Setup test keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);

    // Load CryptoContext without explicit kid (should use active key)
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);

    // Verify context
    assert_eq!(key_ctx.member_handle(), ALICE_MEMBER_HANDLE);
    assert!(!key_ctx.kid().is_empty());
    // Verify pub_key_source works by loading the signer's public key
    let loaded = key_ctx
        .pub_key_source
        .load_public_key(key_ctx.member_handle_id());
    assert!(loaded.is_ok());
}

#[cfg(unix)]
#[test]
fn test_crypto_context_keystore_access_survives_root_path_replacement() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");
    let moved_keystore_root = temp_dir.path().join("keys-original");
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);

    fs::rename(&keystore_root, &moved_keystore_root).unwrap();
    fs::create_dir(&keystore_root).unwrap();

    // The signing path is what reads the key back, so it is what shows the
    // context still reaches the directory it opened rather than the new one.
    let signing = build_signing_context(&key_ctx).unwrap();
    assert_eq!(
        signing.signer_pub.protected.subject_handle,
        ALICE_MEMBER_HANDLE
    );
    assert_eq!(signing.signer_pub.protected.kid, key_ctx.kid());
}

/// The two halves stored under one key directory have to be halves of the same
/// key, so a directory holding a public half that names a different key is
/// refused instead of loaded as the key that was asked for.
#[test]
fn test_crypto_context_load_refuses_a_key_directory_whose_halves_disagree() {
    // Setup test keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    // Ensure there are at least two valid key directories by creating one more.
    let ssh_priv = temp_dir.path().join(".ssh").join("test_ed25519");
    let ssh_pub = load_fixture_ssh_pubkey();
    let (plaintext2, public_key2) =
        crate::test_utils::keygen_helpers::keygen_test(ALICE_MEMBER_HANDLE, &ssh_priv, &ssh_pub)
            .unwrap();
    let private_key2 = crate::test_utils::keygen_helpers::build_test_private_key(
        &plaintext2,
        &public_key2.protected.subject_handle,
        &public_key2.protected.kid,
        &ssh_priv,
        &ssh_pub,
    )
    .unwrap();
    save_key_pair_atomic(
        &keystore_root,
        &public_key2.protected.subject_handle,
        &public_key2.protected.kid,
        &private_key2,
        &public_key2,
    )
    .unwrap();

    // The key the fixture installed, which key2's public half does not belong to.
    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid1 = kids
        .into_iter()
        .find(|kid| *kid != public_key2.protected.kid)
        .unwrap();

    // Put key2's public half, valid in its own right, under kid1.
    let kid1_public_path = keystore_root
        .join(ALICE_MEMBER_HANDLE)
        .join(&kid1)
        .join("public.json");
    fs::write(
        &kid1_public_path,
        serde_json::to_string_pretty(&public_key2).unwrap(),
    )
    .unwrap();

    // Loading kid1 now reaches a directory whose halves name different keys.
    let ssh_pub_for_kdf = fs::read_to_string(temp_dir.path().join(".ssh").join("test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let backend: Box<dyn crate::io::ssh::backend::SignatureBackend> =
        Box::new(crate::test_utils::ed25519_backend::Ed25519DirectBackend::new(&ssh_priv).unwrap());

    let result = load_crypto_context_with_access(
        KeystoreAccess::open(&keystore_root).unwrap(),
        MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap(),
        backend,
        ssh_pub_for_kdf,
        Some(&kid1),
        Some(temp_dir.path().join("workspace")),
    );
    let error = result
        .err()
        .expect("a key directory whose halves disagree must be refused");
    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
    assert!(
        error
            .to_string()
            .contains(public_key2.protected.kid.as_str()),
        "unexpected error: {error}"
    );
}
