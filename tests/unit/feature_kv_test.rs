// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/kv module
//!
//! Tests for KV operations (get/set/unset/list).

use crate::cli_common::ALICE_MEMBER_ID;
use crate::keygen_helpers::make_verified_members;
use crate::test_utils::{
    setup_member_key_context, setup_test_keystore_from_fixtures, setup_test_workspace_from_fixtures,
};
use secretenv::feature::envelope::signature::SigningContext;
use secretenv::feature::kv::encrypt::encrypt_kv_document;
use secretenv::feature::kv::mutate::{set_kv_entry, unset_kv_entry, KvWriteContext};
use secretenv::feature::kv::query::{decrypt_kv_value, list_kv_keys};
use secretenv::format::content::KvEncContent;
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
    let signer_pub = public_key.clone();
    let members = vec![public_key];
    let verified_members = make_verified_members(&members);

    let signing = SigningContext {
        signing_key: &key_ctx.signing_key,
        signer_kid: kid,
        signer_pub,
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
fn test_list_kv_keys() {
    let mut kv_map = std::collections::HashMap::new();
    kv_map.insert(
        "DATABASE_URL".to_string(),
        "postgres://localhost".to_string(),
    );
    kv_map.insert("API_KEY".to_string(), "secret123".to_string());

    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let encrypted = create_test_kv_enc_content(&temp_dir, &kv_map);

    // List keys
    let keys = list_kv_keys(&KvEncContent::new_unchecked(encrypted)).unwrap();

    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&"DATABASE_URL".to_string()));
    assert!(keys.contains(&"API_KEY".to_string()));
}

#[test]
fn test_list_kv_keys_empty() {
    let kv_map = std::collections::HashMap::new();

    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let encrypted = create_test_kv_enc_content(&temp_dir, &kv_map);

    // List keys
    let keys = list_kv_keys(&KvEncContent::new_unchecked(encrypted)).unwrap();

    assert_eq!(keys.len(), 0);
}

#[test]
fn test_decrypt_kv_value() {
    let mut kv_map = std::collections::HashMap::new();
    kv_map.insert(
        "DATABASE_URL".to_string(),
        "postgres://localhost".to_string(),
    );
    kv_map.insert("API_KEY".to_string(), "secret123".to_string());

    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let encrypted = create_test_kv_enc_content(&temp_dir, &kv_map);

    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));

    // Get value
    let encrypted = KvEncContent::new_unchecked(encrypted);
    let value =
        decrypt_kv_value(&encrypted, ALICE_MEMBER_ID, &key_ctx, "DATABASE_URL", false).unwrap();

    assert_eq!(value, "postgres://localhost");
}

#[test]
fn test_decrypt_kv_value_not_found() {
    let mut kv_map = std::collections::HashMap::new();
    kv_map.insert(
        "DATABASE_URL".to_string(),
        "postgres://localhost".to_string(),
    );

    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let encrypted = create_test_kv_enc_content(&temp_dir, &kv_map);

    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));

    // Get non-existent value
    let encrypted = KvEncContent::new_unchecked(encrypted);
    let result = decrypt_kv_value(&encrypted, ALICE_MEMBER_ID, &key_ctx, "NONEXISTENT", false);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

#[test]
fn test_set_kv_entry_new_file() {
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID]);
    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));

    // Set context
    let ctx = KvWriteContext {
        member_id: ALICE_MEMBER_ID.to_string(),
        key_ctx,
        token_codec: Some(TokenCodec::JsonJcs),

        verbose: false,
    };

    // Set new key-value pair (new file)
    let entries = vec![(
        "DATABASE_URL".to_string(),
        "postgres://localhost".to_string(),
    )];
    let result = set_kv_entry(
        None, // No existing content
        &entries,
        &workspace_dir,
        &ctx,
    )
    .unwrap();

    // Verify result
    assert!(result.encrypted.as_str().contains("DATABASE_URL"));
    assert_eq!(result.recipients, vec![ALICE_MEMBER_ID.to_string()]);
}

#[test]
fn test_set_kv_entry_existing_file() {
    // Create existing encrypted content
    let mut kv_map = std::collections::HashMap::new();
    kv_map.insert("API_KEY".to_string(), "secret123".to_string());

    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let existing_content = create_test_kv_enc_content(&temp_dir, &kv_map);

    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));

    // Set context
    let ctx = KvWriteContext {
        member_id: ALICE_MEMBER_ID.to_string(),
        key_ctx,
        token_codec: None, // Preserve existing codec

        verbose: false,
    };

    // Set new key-value pair (existing file - workspace_root not used for recipient lookup)
    let entries = vec![(
        "DATABASE_URL".to_string(),
        "postgres://localhost".to_string(),
    )];
    let existing_content = KvEncContent::new_unchecked(existing_content);
    let result = set_kv_entry(Some(&existing_content), &entries, temp_dir.path(), &ctx).unwrap();

    // Verify result contains both keys
    assert!(result.encrypted.as_str().contains("DATABASE_URL"));
    assert!(result.encrypted.as_str().contains("API_KEY"));
}

#[test]
fn test_unset_kv_entry() {
    // Create existing encrypted content
    let mut kv_map = std::collections::HashMap::new();
    kv_map.insert(
        "DATABASE_URL".to_string(),
        "postgres://localhost".to_string(),
    );
    kv_map.insert("API_KEY".to_string(), "secret123".to_string());

    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let existing_content = create_test_kv_enc_content(&temp_dir, &kv_map);

    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));

    // Unset context
    let ctx = KvWriteContext {
        member_id: ALICE_MEMBER_ID.to_string(),
        key_ctx,
        token_codec: None,

        verbose: false,
    };

    // Unset key
    let existing_content = KvEncContent::new_unchecked(existing_content);
    let result = unset_kv_entry(&existing_content, "API_KEY", &ctx).unwrap();

    // Verify result doesn't contain removed key
    assert!(!result.contains("API_KEY"));
    assert!(result.contains("DATABASE_URL"));
}

#[test]
fn test_unset_kv_entry_not_found() {
    // Create existing encrypted content
    let mut kv_map = std::collections::HashMap::new();
    kv_map.insert(
        "DATABASE_URL".to_string(),
        "postgres://localhost".to_string(),
    );

    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let existing_content = create_test_kv_enc_content(&temp_dir, &kv_map);

    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));

    // Unset context
    let ctx = KvWriteContext {
        member_id: ALICE_MEMBER_ID.to_string(),
        key_ctx,
        token_codec: None,

        verbose: false,
    };

    // Unset non-existent key
    let existing_content = KvEncContent::new_unchecked(existing_content);
    let result = unset_kv_entry(&existing_content, "NONEXISTENT", &ctx);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

#[test]
fn test_set_kv_entry_multiple_entries_new_file() {
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID]);
    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));

    let ctx = KvWriteContext {
        member_id: ALICE_MEMBER_ID.to_string(),
        key_ctx,
        token_codec: Some(TokenCodec::JsonJcs),

        verbose: false,
    };

    let entries = vec![
        (
            "DATABASE_URL".to_string(),
            "postgres://localhost".to_string(),
        ),
        ("API_KEY".to_string(), "secret123".to_string()),
        ("APP_SECRET".to_string(), "my_secret".to_string()),
    ];
    let result = set_kv_entry(None, &entries, &workspace_dir, &ctx).unwrap();

    assert!(result.encrypted.as_str().contains("DATABASE_URL"));
    assert!(result.encrypted.as_str().contains("API_KEY"));
    assert!(result.encrypted.as_str().contains("APP_SECRET"));
    assert_eq!(result.recipients, vec![ALICE_MEMBER_ID.to_string()]);
}

#[test]
fn test_set_kv_entry_multiple_entries_existing_file() {
    // Create existing encrypted content with one key
    let mut kv_map = std::collections::HashMap::new();
    kv_map.insert("EXISTING_KEY".to_string(), "existing_value".to_string());

    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let existing_content = create_test_kv_enc_content(&temp_dir, &kv_map);

    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));

    let ctx = KvWriteContext {
        member_id: ALICE_MEMBER_ID.to_string(),
        key_ctx,
        token_codec: None,

        verbose: false,
    };

    let new_entries = vec![
        ("NEW_KEY_1".to_string(), "value1".to_string()),
        ("NEW_KEY_2".to_string(), "value2".to_string()),
    ];
    let existing_content = KvEncContent::new_unchecked(existing_content);
    let result =
        set_kv_entry(Some(&existing_content), &new_entries, temp_dir.path(), &ctx).unwrap();

    // Verify result contains both existing and new keys
    assert!(result.encrypted.as_str().contains("EXISTING_KEY"));
    assert!(result.encrypted.as_str().contains("NEW_KEY_1"));
    assert!(result.encrypted.as_str().contains("NEW_KEY_2"));
}
