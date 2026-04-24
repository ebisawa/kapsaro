// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/encrypt module
//!
//! Tests for encryption use cases.

use crate::keygen_helpers::build_verified_recipient_key;
use crate::test_utils::ALICE_MEMBER_ID;
use crate::test_utils::{setup_member_key_context, setup_test_keystore_from_fixtures};
use ed25519_dalek::SigningKey;
use secretenv::feature::decrypt::file::decrypt_file_document;
use secretenv::feature::encrypt::encrypt_file_content;
use secretenv::feature::envelope::signature::SigningContext;
use secretenv::feature::kv::decrypt::decrypt_kv_document;
use secretenv::feature::verify::file::verify_file_document;
use secretenv::feature::verify::kv::signature::verify_kv_document;
use secretenv::format::kv::document::parse_kv_document;
use secretenv::io::keystore::storage::{list_kids, load_public_key};
use secretenv::model::file_enc::FileEncDocument;
use secretenv::model::identifiers::format::FILE_ENC_V3;

/// Generate Ed25519 signing key from seed for tests
fn generate_ed25519_keypair(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

#[test]
fn test_encrypt_file_document() {
    // Use keys from fixture keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    // Load CryptoContext to get signing key
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);

    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();

    let signing_key = &key_ctx.signing_key;

    // Input content
    let content = b"Hello, World!";
    let recipients = vec![ALICE_MEMBER_ID.to_string()];
    let attested_members = vec![build_verified_recipient_key(public_key.clone())];

    // Encrypt
    let signing = SigningContext {
        signing_key,
        signer_kid: kid,
        signer_pub: public_key,
        debug: false,
    };
    let encrypted_json =
        encrypt_file_content(content, &recipients, &attested_members, &signing).unwrap();

    // Verify it's valid JSON
    let file_enc_doc: FileEncDocument = serde_json::from_str(&encrypted_json).unwrap();

    // Verify structure
    assert_eq!(file_enc_doc.protected.format, FILE_ENC_V3);
    assert_eq!(
        file_enc_doc.signature.signer_pub.protected.member_id,
        ALICE_MEMBER_ID
    );

    // Decrypt and verify
    let doc: FileEncDocument = serde_json::from_str(&encrypted_json).unwrap();
    let verified_doc = verify_file_document(&doc, false).unwrap();
    let decrypted = decrypt_file_document(
        &verified_doc,
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
fn test_encrypt_file_document_recipient_count_mismatch() {
    // Use keys from fixture keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();
    let signing_key = generate_ed25519_keypair([2u8; 32]);

    // Input content
    let content = b"Hello, World!";
    let recipients = vec![ALICE_MEMBER_ID.to_string(), "bob@example.com".to_string()];
    let signer_pub = public_key.clone();
    let attested_members = vec![build_verified_recipient_key(public_key)]; // Only one member, but two recipients

    // Encrypt should fail due to mismatch
    let signing = SigningContext {
        signing_key: &signing_key,
        signer_kid: kid,
        signer_pub,
        debug: false,
    };
    let result = encrypt_file_content(content, &recipients, &attested_members, &signing);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Recipients count"));
}

#[test]
fn test_encrypt_kv_document_via_inner_api() {
    use secretenv::feature::kv::encrypt::encrypt_kv_document;
    use secretenv::format::token::TokenCodec;
    use std::collections::HashMap;

    // Use keys from fixture keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);

    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();
    let signing_key = &key_ctx.signing_key;

    let mut kv_map = HashMap::new();
    kv_map.insert(
        "DATABASE_URL".to_string(),
        "postgres://localhost".to_string(),
    );
    kv_map.insert("API_KEY".to_string(), "secret123".to_string());

    let attested_members = vec![build_verified_recipient_key(public_key.clone())];

    let signing = SigningContext {
        signing_key,
        signer_kid: kid,
        signer_pub: public_key,
        debug: false,
    };
    let encrypted =
        encrypt_kv_document(&kv_map, &attested_members, &signing, TokenCodec::JsonJcs).unwrap();

    // Verify structure
    assert!(encrypted.starts_with(":SECRETENV_KV 3\n"));
    assert!(encrypted.contains(":HEAD "));
    assert!(encrypted.contains(":WRAP "));
    assert!(encrypted.contains("DATABASE_URL "));
    assert!(encrypted.contains("API_KEY "));

    // Verify signer_pub is always embedded in output signature
    let doc = parse_kv_document(&encrypted).unwrap();
    let sig_token = &doc.signature_token;
    let sig = secretenv::format::schema::document::parse_kv_signature_token(sig_token).unwrap();
    assert_eq!(sig.signer_pub.protected.member_id, ALICE_MEMBER_ID);

    // Decrypt and verify
    let verified_doc = verify_kv_document(&doc, false).unwrap();
    let decrypted_map_zeroizing = decrypt_kv_document(
        &verified_doc,
        ALICE_MEMBER_ID,
        &key_ctx.kid,
        &key_ctx.private_key,
        false,
    )
    .unwrap();
    use secretenv::format::kv::dotenv::build_dotenv_string;
    let decrypted_map: HashMap<String, String> = decrypted_map_zeroizing
        .into_iter()
        .map(|(k, v)| (k, String::from_utf8(v.to_vec()).unwrap()))
        .collect();
    let decrypted = build_dotenv_string(&decrypted_map);
    assert!(decrypted.contains("DATABASE_URL=postgres://localhost"));
    assert!(decrypted.contains("API_KEY=secret123"));
}
