// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for disclosed-flag behavior in feature/kv.

use crate::keygen_helpers::make_verified_members;
use crate::test_utils::{setup_member_key_context, setup_test_keystore_from_fixtures};
use crate::test_utils::{ALICE_MEMBER_ID, BOB_MEMBER_ID};
use secretenv::feature::context::crypto::CryptoContext;
use secretenv::feature::envelope::signature::SigningContext;
use secretenv::feature::kv::encrypt::encrypt_kv_document;
use secretenv::feature::kv::mutate::{
    set_kv_entry_with_recipients, KvRecipientSnapshot, KvSetResult, KvWriteContext,
};
use secretenv::feature::kv::types::KvInputEntry;
use secretenv::feature::rewrap::{rewrap_content, RewrapRequest};
use secretenv::format::content::{EncryptedContent, KvEncContent};
use secretenv::format::kv::document::parse_kv_document;
use secretenv::format::schema::document::parse_kv_entry_token;
use secretenv::format::token::TokenCodec;
use secretenv::io::keystore::storage::{list_kids, load_public_key};
use secretenv::io::workspace::members::{list_active_member_ids, load_member_files};
use secretenv::model::kv_enc::entry::KvEntryValue;
use secretenv::model::kv_enc::line::KvEncLine;
use std::fs;
use tempfile::TempDir;

fn setup_two_member_keystore() -> (TempDir, String, String) {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");
    let alice_kid = list_kids(&keystore_root, ALICE_MEMBER_ID)
        .unwrap()
        .first()
        .unwrap()
        .clone();

    let ssh_pub_content = std::fs::read_to_string(temp_dir.path().join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let ssh_priv = temp_dir.path().join(".ssh/test_ed25519");
    let (bob_private, bob_public) =
        crate::keygen_helpers::keygen_test(BOB_MEMBER_ID, &ssh_priv, &ssh_pub_content).unwrap();
    let bob_kid = bob_public.protected.kid.clone();
    let bob_private_doc = crate::keygen_helpers::create_test_private_key(
        &bob_private,
        &bob_public.protected.member_id,
        &bob_public.protected.kid,
        &ssh_priv,
        &ssh_pub_content,
    )
    .unwrap();
    secretenv::io::keystore::storage::save_key_pair_atomic(
        &keystore_root,
        BOB_MEMBER_ID,
        &bob_kid,
        &bob_private_doc,
        &bob_public,
    )
    .unwrap();

    (temp_dir, alice_kid, bob_kid)
}

fn setup_workspace_members(temp_dir: &TempDir, member_id: &str, kid: &str) {
    let keystore_root = temp_dir.path().join("keys");
    let public_key = load_public_key(&keystore_root, member_id, kid).unwrap();
    let members_dir = temp_dir.path().join("members/active");
    fs::create_dir_all(&members_dir).unwrap();
    fs::create_dir_all(temp_dir.path().join("members/incoming")).unwrap();
    let member_file = members_dir.join(format!("{}.json", member_id));
    fs::write(
        &member_file,
        serde_json::to_string_pretty(&public_key).unwrap(),
    )
    .unwrap();
}

fn extract_disclosed_flags(content: &str) -> Vec<(String, bool)> {
    let document = parse_kv_document(content).unwrap();
    document
        .lines()
        .iter()
        .filter_map(|line| match line {
            KvEncLine::KV { key, token } => {
                let entry: KvEntryValue = parse_kv_entry_token(token).unwrap();
                Some((key.clone(), entry.disclosed))
            }
            _ => None,
        })
        .collect()
}

fn rewrap_kv_content(
    content: &KvEncContent,
    request: &RewrapRequest<'_>,
) -> secretenv::Result<String> {
    rewrap_content(&EncryptedContent::KvEnc(content.clone()), request)
}

fn encrypt_two_member_document(
    temp_dir: &TempDir,
    alice_kid: &str,
    bob_kid: &str,
    key_ctx: &CryptoContext,
) -> String {
    let keystore_root = temp_dir.path().join("keys");
    let alice_pub = load_public_key(&keystore_root, ALICE_MEMBER_ID, alice_kid).unwrap();
    let bob_pub = load_public_key(&keystore_root, BOB_MEMBER_ID, bob_kid).unwrap();
    let members = make_verified_members(&[alice_pub.clone(), bob_pub]);
    let kv_map = std::collections::HashMap::from([
        ("KEY1".to_string(), "value1".to_string()),
        ("KEY2".to_string(), "value2".to_string()),
    ]);

    encrypt_kv_document(
        &kv_map,
        &members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: alice_kid,
            signer_pub: alice_pub.clone(),
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap()
}

fn single_rewrap_request<'a>(
    key_ctx: &'a CryptoContext,
    workspace_root: Option<&'a std::path::Path>,
) -> RewrapRequest<'a> {
    RewrapRequest {
        member_id: ALICE_MEMBER_ID,
        key_ctx,
        workspace_root,
        target_members: None,
        rotate_key: false,
        clear_disclosure_history: false,

        debug: false,
    }
}

fn remove_bob_recipient(
    temp_dir: &TempDir,
    encrypted: String,
    key_ctx: &CryptoContext,
    kid: &str,
) -> String {
    setup_workspace_members(temp_dir, ALICE_MEMBER_ID, kid);
    let request = single_rewrap_request(key_ctx, Some(temp_dir.path()));
    let encrypted = KvEncContent::new_unchecked(encrypted);

    rewrap_kv_content(&encrypted, &request).unwrap()
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

#[test]
fn test_set_kv_entry_resets_disclosed_after_recipient_removal() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(&alice_kid));
    let encrypted = encrypt_two_member_document(&temp_dir, &alice_kid, &bob_kid, &key_ctx);

    let original_flags = extract_disclosed_flags(&encrypted);
    assert!(original_flags.iter().all(|(_, disclosed)| !disclosed));

    let after_remove = remove_bob_recipient(&temp_dir, encrypted, &key_ctx, &alice_kid);
    let flags_after_remove = extract_disclosed_flags(&after_remove);
    assert!(flags_after_remove.iter().all(|(_, disclosed)| *disclosed));

    let ctx = KvWriteContext::new(ALICE_MEMBER_ID, &key_ctx, false);
    let after_remove = KvEncContent::new_unchecked(after_remove);
    let result = set_kv_entry(
        Some(&after_remove),
        &[("KEY1".to_string(), "new_value".to_string())],
        temp_dir.path(),
        &ctx,
    )
    .unwrap();

    let flags_after_set = extract_disclosed_flags(result.encrypted.as_str());
    assert_eq!(flags_after_set.len(), 2);
    for (key, disclosed) in &flags_after_set {
        match key.as_str() {
            "KEY1" => assert!(!disclosed),
            "KEY2" => assert!(*disclosed),
            other => panic!("unexpected key: {}", other),
        }
    }
}

#[test]
fn test_set_kv_entry_new_entry_has_disclosed_false() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(&alice_kid));
    let encrypted = encrypt_two_member_document(&temp_dir, &alice_kid, &bob_kid, &key_ctx);
    let after_remove = remove_bob_recipient(&temp_dir, encrypted, &key_ctx, &alice_kid);

    let ctx = KvWriteContext::new(ALICE_MEMBER_ID, &key_ctx, false);
    let after_remove = KvEncContent::new_unchecked(after_remove);
    let result = set_kv_entry(
        Some(&after_remove),
        &[("KEY3".to_string(), "value3".to_string())],
        temp_dir.path(),
        &ctx,
    )
    .unwrap();

    let flags_after_set = extract_disclosed_flags(result.encrypted.as_str());
    assert_eq!(flags_after_set.len(), 3);
    for (key, disclosed) in &flags_after_set {
        match key.as_str() {
            "KEY1" | "KEY2" => assert!(*disclosed),
            "KEY3" => assert!(!disclosed),
            other => panic!("unexpected key: {}", other),
        }
    }
}
