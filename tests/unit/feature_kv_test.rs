// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/kv module
//!
//! Tests for KV operations (get/set/unset/list).

use crate::keygen_helpers::make_verified_members;
use crate::test_utils::ALICE_MEMBER_ID;
use crate::test_utils::{
    setup_member_key_context, setup_test_keystore_from_fixtures, setup_test_workspace_from_fixtures,
};
use secretenv::feature::envelope::signature::SigningContext;
use secretenv::feature::kv::decrypt::decrypt_kv_single_entry;
use secretenv::feature::kv::encrypt::encrypt_kv_document;
use secretenv::feature::kv::mutate::{
    set_kv_entry_with_recipients, unset_kv_entry_with_recipients, KvRecipientSnapshot, KvSetResult,
    KvWriteContext,
};
use secretenv::feature::kv::types::KvInputEntry;
use secretenv::feature::verify::kv::signature::verify_kv_content;
use secretenv::format::content::KvEncContent;
use secretenv::format::kv::enc::canonical::parse_kv_wrap;
use secretenv::format::token::TokenCodec;
use secretenv::io::keystore::storage::{list_kids, load_public_key};
use secretenv::io::workspace::members::{list_active_member_ids, load_member_files};
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
    let signer_pub = public_key.clone();
    let members = vec![public_key];
    let verified_members = make_verified_members(&members);

    let signing = SigningContext {
        signing_key: &key_ctx.signing_key,
        signer_kid: kid,
        signer_pub,
        debug: false,
    };
    encrypt_kv_document(kv_map, &verified_members, &signing, TokenCodec::JsonJcs).unwrap()
}

fn list_kv_keys(content: &KvEncContent) -> secretenv::Result<Vec<String>> {
    let mut keys = content
        .parse()?
        .lines()
        .iter()
        .filter_map(|line| match line {
            secretenv::model::kv_enc::line::KvEncLine::KV { key, .. } => Some(key.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    keys.sort();
    Ok(keys)
}

fn decrypt_kv_value(
    content: &KvEncContent,
    member_id: &str,
    key_ctx: &secretenv::feature::context::crypto::CryptoContext,
    key: &str,
) -> secretenv::Result<String> {
    let verified = verify_kv_content(content, false)?;
    let value = decrypt_kv_single_entry(
        &verified,
        member_id,
        &key_ctx.kid,
        &key_ctx.private_key,
        key,
        false,
    )?;
    String::from_utf8(value.to_vec()).map_err(|e| secretenv::Error::Parse {
        message: format!("Invalid UTF-8 in decrypted value: {}", e),
        source: Some(Box::new(e)),
    })
}

fn build_recipient_snapshot(
    workspace_root: &std::path::Path,
) -> secretenv::Result<KvRecipientSnapshot> {
    let member_ids = list_active_member_ids(workspace_root)?;
    let public_keys = load_member_files(workspace_root, &member_ids)?;
    let verified_members =
        secretenv::feature::verify::public_key::verify_recipient_public_keys(&public_keys, false)?;
    Ok(KvRecipientSnapshot {
        member_ids,
        verified_members,
    })
}

fn set_kv_entry(
    existing_content: Option<&KvEncContent>,
    entries: &[(String, String)],
    workspace_root: &std::path::Path,
    ctx: &KvWriteContext<'_>,
) -> secretenv::Result<KvSetResult> {
    let recipients = build_recipient_snapshot(workspace_root)?;
    let entries = entries
        .iter()
        .map(|(key, value)| KvInputEntry::new(key.clone(), value.clone()))
        .collect::<Vec<_>>();
    set_kv_entry_with_recipients(existing_content, &entries, &recipients, ctx)
}

fn unset_kv_entry(
    content: &KvEncContent,
    key: &str,
    ctx: &KvWriteContext<'_>,
) -> secretenv::Result<String> {
    let workspace_root =
        ctx.key_ctx
            .workspace_path
            .as_deref()
            .ok_or_else(|| secretenv::Error::Config {
                message: "Workspace is required for kv mutation".to_string(),
            })?;
    let recipients = build_recipient_snapshot(workspace_root)?;
    unset_kv_entry_with_recipients(content, key, &recipients, ctx)
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
    let kv_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();

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
    let value = decrypt_kv_value(&encrypted, ALICE_MEMBER_ID, &key_ctx, "DATABASE_URL").unwrap();

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
    let result = decrypt_kv_value(&encrypted, ALICE_MEMBER_ID, &key_ctx, "NONEXISTENT");

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
    let mut ctx = KvWriteContext::new(ALICE_MEMBER_ID, &key_ctx, false);
    ctx.token_codec = Some(TokenCodec::JsonJcs);

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
    let ctx = KvWriteContext::new(ALICE_MEMBER_ID, &key_ctx, false);

    // Set new key-value pair (existing file - workspace_root not used for recipient lookup)
    let entries = vec![(
        "DATABASE_URL".to_string(),
        "postgres://localhost".to_string(),
    )];
    let existing_content = KvEncContent::new_unchecked(existing_content);
    let workspace_dir = temp_dir.path().join("workspace");
    let result = set_kv_entry(Some(&existing_content), &entries, &workspace_dir, &ctx).unwrap();

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
    let ctx = KvWriteContext::new(ALICE_MEMBER_ID, &key_ctx, false);

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
    let ctx = KvWriteContext::new(ALICE_MEMBER_ID, &key_ctx, false);

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

    let mut ctx = KvWriteContext::new(ALICE_MEMBER_ID, &key_ctx, false);
    ctx.token_codec = Some(TokenCodec::JsonJcs);

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

    let ctx = KvWriteContext::new(ALICE_MEMBER_ID, &key_ctx, false);

    let new_entries = vec![
        ("NEW_KEY_1".to_string(), "value1".to_string()),
        ("NEW_KEY_2".to_string(), "value2".to_string()),
    ];
    let existing_content = KvEncContent::new_unchecked(existing_content);
    let workspace_dir = temp_dir.path().join("workspace");
    let result = set_kv_entry(Some(&existing_content), &new_entries, &workspace_dir, &ctx).unwrap();

    // Verify result contains both existing and new keys
    assert!(result.encrypted.as_str().contains("EXISTING_KEY"));
    assert!(result.encrypted.as_str().contains("NEW_KEY_1"));
    assert!(result.encrypted.as_str().contains("NEW_KEY_2"));
}

#[test]
fn test_set_kv_entry_existing_file_uses_current_workspace_recipients() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID, "bob@example.com"]);
    let keystore_root = temp_dir.path().join("keys");
    let kid = list_kids(&keystore_root, ALICE_MEMBER_ID)
        .unwrap()
        .first()
        .unwrap()
        .clone();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(&kid));
    let existing_content = KvEncContent::new_unchecked(create_test_kv_enc_content(
        &temp_dir,
        &std::collections::HashMap::from([("API_KEY".to_string(), "secret123".to_string())]),
    ));
    let recipients = build_recipient_snapshot(&workspace_dir).unwrap();
    let ctx = KvWriteContext::new(ALICE_MEMBER_ID, &key_ctx, false);

    let result = set_kv_entry_with_recipients(
        Some(&existing_content),
        &[KvInputEntry::new("DATABASE_URL", "postgres://localhost")],
        &recipients,
        &ctx,
    )
    .unwrap();

    let (_, _, wrap) = parse_kv_wrap(result.encrypted.as_str()).unwrap();
    let mut rids = wrap
        .wrap
        .iter()
        .map(|item| item.rid.clone())
        .collect::<Vec<_>>();
    rids.sort();
    assert_eq!(
        rids,
        vec![ALICE_MEMBER_ID.to_string(), "bob@example.com".to_string()]
    );
}

#[test]
fn test_unset_kv_entry_existing_file_uses_current_workspace_recipients() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID, "bob@example.com"]);
    let keystore_root = temp_dir.path().join("keys");
    let kid = list_kids(&keystore_root, ALICE_MEMBER_ID)
        .unwrap()
        .first()
        .unwrap()
        .clone();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(&kid));
    let existing_content = KvEncContent::new_unchecked(create_test_kv_enc_content(
        &temp_dir,
        &std::collections::HashMap::from([("API_KEY".to_string(), "secret123".to_string())]),
    ));
    let recipients = build_recipient_snapshot(&workspace_dir).unwrap();
    let ctx = KvWriteContext::new(ALICE_MEMBER_ID, &key_ctx, false);

    let result =
        unset_kv_entry_with_recipients(&existing_content, "API_KEY", &recipients, &ctx).unwrap();

    let (_, _, wrap) = parse_kv_wrap(&result).unwrap();
    let mut rids = wrap
        .wrap
        .iter()
        .map(|item| item.rid.clone())
        .collect::<Vec<_>>();
    rids.sort();
    assert_eq!(
        rids,
        vec![ALICE_MEMBER_ID.to_string(), "bob@example.com".to_string()]
    );
}

#[test]
fn test_set_kv_entry_new_file_uses_recipients_snapshot_not_pub_key_source() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_ID, "bob@example.com"]);
    let keystore_root = temp_dir.path().join("keys");
    let kid = list_kids(&keystore_root, ALICE_MEMBER_ID)
        .unwrap()
        .first()
        .unwrap()
        .clone();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(&kid));
    std::fs::remove_dir_all(keystore_root.join("bob@example.com")).unwrap();
    let recipients = build_recipient_snapshot(&workspace_dir).unwrap();
    let mut ctx = KvWriteContext::new(ALICE_MEMBER_ID, &key_ctx, false);
    ctx.token_codec = Some(TokenCodec::JsonJcs);

    let result = set_kv_entry_with_recipients(
        None,
        &[KvInputEntry::new("DATABASE_URL", "postgres://localhost")],
        &recipients,
        &ctx,
    )
    .unwrap();

    let (_, _, wrap) = parse_kv_wrap(result.encrypted.as_str()).unwrap();
    let mut rids = wrap
        .wrap
        .iter()
        .map(|item| item.rid.clone())
        .collect::<Vec<_>>();
    rids.sort();
    assert_eq!(
        rids,
        vec![ALICE_MEMBER_ID.to_string(), "bob@example.com".to_string()]
    );
}
