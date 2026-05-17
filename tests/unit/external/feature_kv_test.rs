// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/kv module
//!
//! Tests for KV operations (get/set/unset/list).

use crate::keygen_helpers::build_verified_recipient_keys;
use crate::test_utils::ALICE_MEMBER_HANDLE;
use crate::test_utils::{
    setup_member_key_context, setup_test_keystore_from_fixtures, setup_test_workspace_from_fixtures,
};
use secretenv_core::cli_api::test_support::operations::envelope::signature::SigningContext;
use secretenv_core::cli_api::test_support::operations::kv::decrypt::decrypt_kv_single_entry;
use secretenv_core::cli_api::test_support::operations::kv::encrypt::encrypt_kv_document;
use secretenv_core::cli_api::test_support::operations::kv::mutate::{
    set_kv_entry_with_recipients, unset_kv_entry_with_recipients, KvRecipientSnapshot, KvSetResult,
    KvWriteContext,
};
use secretenv_core::cli_api::test_support::operations::kv::types::KvInputEntry;
use secretenv_core::cli_api::test_support::operations::verify::kv::signature::verify_kv_content;
use secretenv_core::cli_api::test_support::storage::keystore::storage::{
    list_kids, load_public_key,
};
use secretenv_core::cli_api::test_support::storage::workspace::members::{
    list_active_member_handles, load_member_files,
};
use secretenv_core::cli_api::test_support::wire::content::KvEncContent;
use secretenv_core::cli_api::test_support::wire::kv::enc::canonical::parse_kv_wrap;
use secretenv_core::cli_api::test_support::wire::token::TokenCodec;
use tempfile::TempDir;

fn build_test_kv_enc_content(
    temp_dir: &TempDir,
    kv_map: &std::collections::HashMap<String, String>,
) -> String {
    let keystore_root = temp_dir.path().join("keys");

    // Get public key from keystore first
    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, kid).unwrap();

    // Load CryptoContext to get signing key
    let key_ctx = setup_member_key_context(temp_dir, ALICE_MEMBER_HANDLE, Some(kid));
    let signer_pub = public_key.clone();
    let members = vec![public_key];
    let verified_members = build_verified_recipient_keys(&members);

    let signing = SigningContext {
        signing_key: &key_ctx.signing_key,
        signer_kid: kid,
        signer_pub,
        debug: false,
    };
    encrypt_kv_document(kv_map, &verified_members, &signing, TokenCodec::JsonJcs).unwrap()
}

fn list_kv_keys(content: &KvEncContent) -> secretenv_core::Result<Vec<String>> {
    let mut keys = content
        .parse()?
        .lines()
        .iter()
        .filter_map(|line| match line {
            secretenv_core::cli_api::test_support::domain::kv_enc::line::KvEncLine::KV {
                key,
                ..
            } => Some(key.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    keys.sort();
    Ok(keys)
}

fn decrypt_kv_value(
    content: &KvEncContent,
    member_handle: &str,
    key_ctx: &secretenv_core::cli_api::test_support::operations::context::crypto::CryptoContext,
    key: &str,
) -> secretenv_core::Result<String> {
    let verified = verify_kv_content(content, false)?;
    let value = decrypt_kv_single_entry(
        &verified,
        member_handle,
        &key_ctx.kid,
        &key_ctx.private_key,
        key,
        false,
    )?;
    String::from_utf8(value.to_vec()).map_err(|e| {
        secretenv_core::Error::build_parse_error_with_source(
            format!("Invalid UTF-8 in decrypted value: {}", e),
            e,
        )
    })
}

fn build_recipient_snapshot(
    workspace_root: &std::path::Path,
) -> secretenv_core::Result<KvRecipientSnapshot> {
    let member_handles = list_active_member_handles(workspace_root)?;
    let public_keys = load_member_files(workspace_root, &member_handles)?;
    let verified_members =
        secretenv_core::cli_api::test_support::operations::verify::public_key::verify_recipient_public_keys(
            &public_keys,
            false,
        )?;
    Ok(KvRecipientSnapshot {
        member_handles,
        verified_members,
    })
}

fn set_kv_entry(
    existing_content: Option<&KvEncContent>,
    entries: &[(String, String)],
    workspace_root: &std::path::Path,
    ctx: &KvWriteContext<'_>,
) -> secretenv_core::Result<KvSetResult> {
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
) -> secretenv_core::Result<String> {
    let workspace_root = ctx.key_ctx.workspace_path.as_deref().ok_or_else(|| {
        secretenv_core::Error::build_config_error(
            "Workspace is required for kv mutation".to_string(),
        )
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

    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let encrypted = build_test_kv_enc_content(&temp_dir, &kv_map);

    // List keys
    let keys = list_kv_keys(&KvEncContent::new_unchecked(encrypted)).unwrap();

    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&"DATABASE_URL".to_string()));
    assert!(keys.contains(&"API_KEY".to_string()));
}

#[test]
fn test_list_kv_keys_empty() {
    let kv_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let encrypted = build_test_kv_enc_content(&temp_dir, &kv_map);

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

    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let encrypted = build_test_kv_enc_content(&temp_dir, &kv_map);

    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));

    // Get value
    let encrypted = KvEncContent::new_unchecked(encrypted);
    let value =
        decrypt_kv_value(&encrypted, ALICE_MEMBER_HANDLE, &key_ctx, "DATABASE_URL").unwrap();

    assert_eq!(value, "postgres://localhost");
}

#[test]
fn test_decrypt_kv_value_not_found() {
    let mut kv_map = std::collections::HashMap::new();
    kv_map.insert(
        "DATABASE_URL".to_string(),
        "postgres://localhost".to_string(),
    );

    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let encrypted = build_test_kv_enc_content(&temp_dir, &kv_map);

    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));

    // Get non-existent value
    let encrypted = KvEncContent::new_unchecked(encrypted);
    let result = decrypt_kv_value(&encrypted, ALICE_MEMBER_HANDLE, &key_ctx, "NONEXISTENT");

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

#[test]
fn test_set_kv_entry_new_file() {
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));

    // Set context
    let mut ctx = KvWriteContext::new(ALICE_MEMBER_HANDLE, &key_ctx, false);
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
    assert_eq!(result.recipients, vec![ALICE_MEMBER_HANDLE.to_string()]);
}

#[test]
fn test_set_kv_entry_existing_file() {
    // Create existing encrypted content
    let mut kv_map = std::collections::HashMap::new();
    kv_map.insert("API_KEY".to_string(), "secret123".to_string());

    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let existing_content = build_test_kv_enc_content(&temp_dir, &kv_map);

    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));

    // Set context
    let ctx = KvWriteContext::new(ALICE_MEMBER_HANDLE, &key_ctx, false);

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

    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let existing_content = build_test_kv_enc_content(&temp_dir, &kv_map);

    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));

    // Unset context
    let ctx = KvWriteContext::new(ALICE_MEMBER_HANDLE, &key_ctx, false);

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

    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let existing_content = build_test_kv_enc_content(&temp_dir, &kv_map);

    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));

    // Unset context
    let ctx = KvWriteContext::new(ALICE_MEMBER_HANDLE, &key_ctx, false);

    // Unset non-existent key
    let existing_content = KvEncContent::new_unchecked(existing_content);
    let result = unset_kv_entry(&existing_content, "NONEXISTENT", &ctx);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

#[test]
fn test_set_kv_entry_multiple_entries_new_file() {
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));

    let mut ctx = KvWriteContext::new(ALICE_MEMBER_HANDLE, &key_ctx, false);
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
    assert_eq!(result.recipients, vec![ALICE_MEMBER_HANDLE.to_string()]);
}

#[test]
fn test_set_kv_entry_multiple_entries_existing_file() {
    // Create existing encrypted content with one key
    let mut kv_map = std::collections::HashMap::new();
    kv_map.insert("EXISTING_KEY".to_string(), "existing_value".to_string());

    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let existing_content = build_test_kv_enc_content(&temp_dir, &kv_map);

    let keystore_root = temp_dir.path().join("keys");
    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));

    let ctx = KvWriteContext::new(ALICE_MEMBER_HANDLE, &key_ctx, false);

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
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, "bob@example.com"]);
    let keystore_root = temp_dir.path().join("keys");
    let kid = list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
        .unwrap()
        .first()
        .unwrap()
        .clone();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&kid));
    let existing_content = KvEncContent::new_unchecked(build_test_kv_enc_content(
        &temp_dir,
        &std::collections::HashMap::from([("API_KEY".to_string(), "secret123".to_string())]),
    ));
    let recipients = build_recipient_snapshot(&workspace_dir).unwrap();
    let ctx = KvWriteContext::new(ALICE_MEMBER_HANDLE, &key_ctx, false);

    let result = set_kv_entry_with_recipients(
        Some(&existing_content),
        &[KvInputEntry::new("DATABASE_URL", "postgres://localhost")],
        &recipients,
        &ctx,
    )
    .unwrap();

    let (_, _, wrap) = parse_kv_wrap(result.encrypted.as_str()).unwrap();
    let mut recipient_handles = wrap
        .wrap
        .iter()
        .map(|item| item.recipient_handle.clone())
        .collect::<Vec<_>>();
    recipient_handles.sort();
    assert_eq!(
        recipient_handles,
        vec![
            ALICE_MEMBER_HANDLE.to_string(),
            "bob@example.com".to_string()
        ]
    );
}

#[test]
fn test_unset_kv_entry_existing_file_uses_current_workspace_recipients() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, "bob@example.com"]);
    let keystore_root = temp_dir.path().join("keys");
    let kid = list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
        .unwrap()
        .first()
        .unwrap()
        .clone();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&kid));
    let existing_content = KvEncContent::new_unchecked(build_test_kv_enc_content(
        &temp_dir,
        &std::collections::HashMap::from([("API_KEY".to_string(), "secret123".to_string())]),
    ));
    let recipients = build_recipient_snapshot(&workspace_dir).unwrap();
    let ctx = KvWriteContext::new(ALICE_MEMBER_HANDLE, &key_ctx, false);

    let result =
        unset_kv_entry_with_recipients(&existing_content, "API_KEY", &recipients, &ctx).unwrap();

    let (_, _, wrap) = parse_kv_wrap(&result).unwrap();
    let mut recipient_handles = wrap
        .wrap
        .iter()
        .map(|item| item.recipient_handle.clone())
        .collect::<Vec<_>>();
    recipient_handles.sort();
    assert_eq!(
        recipient_handles,
        vec![
            ALICE_MEMBER_HANDLE.to_string(),
            "bob@example.com".to_string()
        ]
    );
}

#[test]
fn test_set_kv_entry_new_file_uses_recipients_snapshot_not_pub_key_source() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, "bob@example.com"]);
    let keystore_root = temp_dir.path().join("keys");
    let kid = list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
        .unwrap()
        .first()
        .unwrap()
        .clone();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&kid));
    std::fs::remove_dir_all(keystore_root.join("bob@example.com")).unwrap();
    let recipients = build_recipient_snapshot(&workspace_dir).unwrap();
    let mut ctx = KvWriteContext::new(ALICE_MEMBER_HANDLE, &key_ctx, false);
    ctx.token_codec = Some(TokenCodec::JsonJcs);

    let result = set_kv_entry_with_recipients(
        None,
        &[KvInputEntry::new("DATABASE_URL", "postgres://localhost")],
        &recipients,
        &ctx,
    )
    .unwrap();

    let (_, _, wrap) = parse_kv_wrap(result.encrypted.as_str()).unwrap();
    let mut recipient_handles = wrap
        .wrap
        .iter()
        .map(|item| item.recipient_handle.clone())
        .collect::<Vec<_>>();
    recipient_handles.sort();
    assert_eq!(
        recipient_handles,
        vec![
            ALICE_MEMBER_HANDLE.to_string(),
            "bob@example.com".to_string()
        ]
    );
}
