// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for core/usecase/run module
//!
//! Tests for run use case (build env from kv-enc files).

use crate::cli_common::ALICE_MEMBER_ID;
use crate::keygen_helpers::make_verified_members;
use crate::test_utils::{setup_member_key_context, setup_test_keystore_from_fixtures};
use secretenv::feature::envelope::signature::SigningContext;
use secretenv::feature::kv::encrypt::encrypt_kv_document;
use secretenv::feature::run::build_env_from_kv_contents;
use secretenv::format::token::TokenCodec;
use secretenv::io::keystore::storage::{list_kids, load_public_key};
use tempfile::TempDir;

fn create_test_kv_enc_content(
    temp_dir: &TempDir,
    kv_map: &std::collections::HashMap<String, String>,
) -> String {
    let keystore_root = temp_dir.path().join("keys");

    // Get public key from keystore first
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();

    // Load CryptoContext to get signing key
    let key_ctx = setup_member_key_context(temp_dir, ALICE_MEMBER_ID, Some(kid));
    let recipients = vec![ALICE_MEMBER_ID.to_string()];
    let members = vec![public_key.clone()];
    let verified_members = make_verified_members(&members);

    let signing = SigningContext {
        signing_key: &key_ctx.signing_key,
        signer_kid: kid,
        signer_pub: public_key,
        debug: false,
    };
    encrypt_kv_document(
        kv_map,
        &recipients,
        &verified_members,
        &signing,
        TokenCodec::JsonJcs,
    )
    .unwrap()
}

#[test]
fn test_build_env_from_kv_contents_single_file() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));

    // Create kv-enc content
    let mut kv_map = std::collections::HashMap::new();
    kv_map.insert(
        "DATABASE_URL".to_string(),
        "postgres://localhost".to_string(),
    );
    kv_map.insert("API_KEY".to_string(), "secret123".to_string());

    let encrypted = create_test_kv_enc_content(&temp_dir, &kv_map);

    // Build env
    let env_vars =
        build_env_from_kv_contents(&[&encrypted], ALICE_MEMBER_ID, &key_ctx, false).unwrap();

    // Verify env vars
    assert_eq!(
        env_vars.get("DATABASE_URL"),
        Some(&"postgres://localhost".to_string())
    );
    assert_eq!(env_vars.get("API_KEY"), Some(&"secret123".to_string()));
}

#[test]
fn test_build_env_from_kv_contents_multiple_files() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));

    // Create first kv-enc content
    let mut kv_map1 = std::collections::HashMap::new();
    kv_map1.insert(
        "DATABASE_URL".to_string(),
        "postgres://localhost".to_string(),
    );
    let encrypted1 = create_test_kv_enc_content(&temp_dir, &kv_map1);

    // Create second kv-enc content
    let mut kv_map2 = std::collections::HashMap::new();
    kv_map2.insert("API_KEY".to_string(), "secret123".to_string());
    let encrypted2 = create_test_kv_enc_content(&temp_dir, &kv_map2);

    // Build env from multiple files
    let env_vars = build_env_from_kv_contents(
        &[&encrypted1, &encrypted2],
        ALICE_MEMBER_ID,
        &key_ctx,
        false,
    )
    .unwrap();

    // Verify env vars from both files
    assert_eq!(
        env_vars.get("DATABASE_URL"),
        Some(&"postgres://localhost".to_string())
    );
    assert_eq!(env_vars.get("API_KEY"), Some(&"secret123".to_string()));
}

#[test]
fn test_build_env_from_kv_contents_overwrite() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));

    // Create first kv-enc content
    let mut kv_map1 = std::collections::HashMap::new();
    kv_map1.insert("API_KEY".to_string(), "old_secret".to_string());
    let encrypted1 = create_test_kv_enc_content(&temp_dir, &kv_map1);

    // Create second kv-enc content with same key
    let mut kv_map2 = std::collections::HashMap::new();
    kv_map2.insert("API_KEY".to_string(), "new_secret".to_string());
    let encrypted2 = create_test_kv_enc_content(&temp_dir, &kv_map2);

    // Build env from multiple files (later file should overwrite)
    let env_vars = build_env_from_kv_contents(
        &[&encrypted1, &encrypted2],
        ALICE_MEMBER_ID,
        &key_ctx,
        false,
    )
    .unwrap();

    // Verify later value overwrites earlier value
    assert_eq!(env_vars.get("API_KEY"), Some(&"new_secret".to_string()));
}
