// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/rewrap/kv module (KV document rewrap operations).

use crate::keygen_helpers::make_verified_members;
use crate::test_utils::{
    setup_member_key_context, setup_test_keystore_from_fixtures,
    sync_active_public_key_to_workspace, update_active_private_key_expires_at,
};
use crate::test_utils::{ALICE_MEMBER_ID, BOB_MEMBER_ID};
use secretenv::feature::context::crypto::CryptoContext;
use secretenv::feature::envelope::signature::SigningContext;
use secretenv::feature::kv::encrypt::encrypt_kv_document;
use secretenv::feature::rewrap::{rewrap_content, RewrapRequest};
use secretenv::format::content::{EncryptedContent, KvEncContent};
use secretenv::format::kv::document::parse_kv_document;
use secretenv::format::kv::dotenv::parse_dotenv;
use secretenv::format::schema::document::{parse_kv_entry_token, parse_kv_wrap_token};
use secretenv::format::token::TokenCodec;
use secretenv::io::keystore::storage::{list_kids, load_public_key};
use secretenv::model::kv_enc::entry::KvEntryValue;
use secretenv::model::kv_enc::header::KvWrap;
use secretenv::model::kv_enc::line::KvEncLine;
use std::fs;
use tempfile::TempDir;

/// Create workspace members directory with the member's public key file.
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

fn single_rewrap_request<'a>(
    key_ctx: &'a CryptoContext,
    workspace_root: Option<&'a std::path::Path>,
    rotate_key: bool,
    clear_disclosure_history: bool,
    debug: bool,
) -> RewrapRequest<'a> {
    RewrapRequest {
        member_id: ALICE_MEMBER_ID,
        key_ctx,
        workspace_root,
        target_members: None,
        rotate_key,
        clear_disclosure_history,

        debug,
    }
}

fn rewrap_kv_content(
    content: &KvEncContent,
    request: &RewrapRequest<'_>,
) -> secretenv::Result<String> {
    rewrap_content(&EncryptedContent::KvEnc(content.clone()), request)
}

/// Encrypt a simple KV document for alice (single recipient).
fn encrypt_kv_for_alice(temp_dir: &TempDir, kid: &str, key_ctx: &CryptoContext) -> String {
    let keystore_root = temp_dir.path().join("keys");
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();
    let members = make_verified_members(std::slice::from_ref(&public_key));
    let kv_map = parse_dotenv("DATABASE_URL=postgres://localhost\n").unwrap();
    encrypt_kv_document(
        &kv_map,
        &members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: kid,
            signer_pub: public_key.clone(),
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap()
}

/// Encrypt a KV document for alice and bob (two recipients).
fn encrypt_kv_for_alice_and_bob(
    temp_dir: &TempDir,
    alice_kid: &str,
    bob_kid: &str,
    key_ctx: &CryptoContext,
) -> String {
    let keystore_root = temp_dir.path().join("keys");
    let alice_pub = load_public_key(&keystore_root, ALICE_MEMBER_ID, alice_kid).unwrap();
    let bob_pub = load_public_key(&keystore_root, BOB_MEMBER_ID, bob_kid).unwrap();
    let members = make_verified_members(&[alice_pub.clone(), bob_pub]);
    let kv_map = parse_dotenv("DATABASE_URL=postgres://localhost\n").unwrap();
    encrypt_kv_document(
        &kv_map,
        &members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: alice_kid,
            signer_pub: alice_pub,
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap()
}

/// Setup a two-member keystore (alice + bob) in one TempDir.
///
/// Returns (temp_dir, alice_kid, bob_kid).
fn setup_two_member_keystore() -> (TempDir, String, String) {
    // Start with alice keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let alice_kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let alice_kid = alice_kids.first().unwrap().clone();

    // Generate bob's keys in the same keystore
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

#[test]
fn test_rewrap_kv_document_succeeds() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, kid);

    let encrypted = encrypt_kv_for_alice(&temp_dir, kid, &key_ctx);

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, false, false);
    let encrypted = KvEncContent::new_unchecked(encrypted);
    let result = rewrap_kv_content(&encrypted, &request);

    assert!(
        result.is_ok(),
        "rewrap_kv_document must succeed: {:?}",
        result.err()
    );

    // Rewrapped content must be parseable
    let rewrapped = result.unwrap();
    let doc = parse_kv_document(&rewrapped);
    assert!(
        doc.is_ok(),
        "rewrapped content must be parseable: {:?}",
        doc.err()
    );
}

#[test]
fn test_rewrap_kv_document_rotate_key() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, kid);

    let encrypted = encrypt_kv_for_alice(&temp_dir, kid, &key_ctx);

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), true, false, false);
    let encrypted = KvEncContent::new_unchecked(encrypted);
    let result = rewrap_kv_content(&encrypted, &request);

    assert!(
        result.is_ok(),
        "rewrap with rotate_key must succeed: {:?}",
        result.err()
    );

    // Rotated content must be parseable and differ from original (new WRAP tokens)
    let rewrapped = result.unwrap();
    let doc = parse_kv_document(&rewrapped);
    assert!(
        doc.is_ok(),
        "rotated content must be parseable: {:?}",
        doc.err()
    );

    // WRAP tokens should differ because the master key was rotated
    let original_wrap: String = encrypted
        .as_str()
        .lines()
        .find(|l| l.starts_with(":WRAP "))
        .unwrap()
        .to_string();
    let rotated_wrap: String = rewrapped
        .lines()
        .find(|l| l.starts_with(":WRAP "))
        .unwrap()
        .to_string();
    assert_ne!(
        original_wrap, rotated_wrap,
        "WRAP token must change after key rotation"
    );
}

#[test]
fn test_rewrap_kv_succeeds_when_only_old_self_wrap_exists() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);

    let old_key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    let old_kid = old_key_ctx.kid.to_string();
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, &old_kid);
    let encrypted = encrypt_kv_for_alice(&temp_dir, &old_kid, &old_key_ctx);

    update_active_private_key_expires_at(temp_dir.path(), ALICE_MEMBER_ID, "2028-01-01T00:00:00Z");
    sync_active_public_key_to_workspace(temp_dir.path(), temp_dir.path(), ALICE_MEMBER_ID).unwrap();

    let new_key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);
    let new_kid = new_key_ctx.kid.to_string();
    assert_ne!(new_kid, old_kid);

    let request = single_rewrap_request(&new_key_ctx, Some(temp_dir.path()), false, false, false);
    let encrypted = KvEncContent::new_unchecked(encrypted);
    let result = rewrap_kv_content(&encrypted, &request);

    assert!(
        result.is_ok(),
        "rewrap with only old self wrap must succeed: {:?}",
        result.err()
    );

    let rewrapped = result.unwrap();
    let wrap_token = rewrapped
        .lines()
        .find(|l| l.starts_with(":WRAP "))
        .unwrap()
        .strip_prefix(":WRAP ")
        .unwrap();
    let wrap_data: KvWrap = parse_kv_wrap_token(wrap_token).unwrap();
    let alice_wrap = wrap_data
        .wrap
        .iter()
        .find(|wrap| wrap.rid == ALICE_MEMBER_ID)
        .unwrap();
    assert_eq!(alice_wrap.kid, new_kid);
}

#[test]
fn test_rewrap_kv_add_recipient() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(&alice_kid));

    // Encrypt for alice only
    let encrypted = encrypt_kv_for_alice(&temp_dir, &alice_kid, &key_ctx);

    // Setup workspace with both alice and bob as active members
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, &alice_kid);
    setup_workspace_members(&temp_dir, BOB_MEMBER_ID, &bob_kid);

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, false, false);
    let encrypted = KvEncContent::new_unchecked(encrypted);
    let result = rewrap_kv_content(&encrypted, &request);

    assert!(
        result.is_ok(),
        "rewrap adding recipient must succeed: {:?}",
        result.err()
    );

    // Parse the rewrapped WRAP token to verify bob was added as a recipient
    let rewrapped = result.unwrap();
    let wrap_token = rewrapped
        .lines()
        .find(|l| l.starts_with(":WRAP "))
        .unwrap()
        .strip_prefix(":WRAP ")
        .unwrap();
    let wrap_data: secretenv::model::kv_enc::header::KvWrap =
        parse_kv_wrap_token(wrap_token).unwrap();
    let recipient_ids: Vec<&str> = wrap_data.wrap.iter().map(|w| w.rid.as_str()).collect();
    assert!(
        recipient_ids.contains(&BOB_MEMBER_ID),
        "rewrapped WRAP must include bob as a recipient, got: {:?}",
        recipient_ids
    );
    assert!(
        recipient_ids.contains(&ALICE_MEMBER_ID),
        "rewrapped WRAP must still include alice as a recipient, got: {:?}",
        recipient_ids
    );
}

#[test]
fn test_rewrap_kv_remove_recipient() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(&alice_kid));

    // Encrypt for alice and bob
    let encrypted = encrypt_kv_for_alice_and_bob(&temp_dir, &alice_kid, &bob_kid, &key_ctx);

    // Setup workspace with only alice as active member (bob removed)
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, &alice_kid);
    // Do NOT add bob to workspace members => he will be removed during rewrap

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, false, false);
    let encrypted = KvEncContent::new_unchecked(encrypted);
    let result = rewrap_kv_content(&encrypted, &request);

    assert!(
        result.is_ok(),
        "rewrap removing recipient must succeed: {:?}",
        result.err()
    );

    // After removal, bob should not be in the WRAP recipients
    // but may appear in removed_recipients disclosure history
    let rewrapped = result.unwrap();
    let doc = parse_kv_document(&rewrapped);
    assert!(
        doc.is_ok(),
        "rewrapped content must be parseable: {:?}",
        doc.err()
    );
}

#[test]
fn test_rewrap_kv_clear_disclosure_history() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(&alice_kid));

    // Encrypt for alice and bob
    let encrypted = encrypt_kv_for_alice_and_bob(&temp_dir, &alice_kid, &bob_kid, &key_ctx);

    // Setup workspace with only alice (bob removed) => removal creates disclosure history
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, &alice_kid);

    let remove_request =
        single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, false, false);
    let encrypted = KvEncContent::new_unchecked(encrypted);
    let after_remove = rewrap_kv_content(&encrypted, &remove_request).unwrap();

    // Now rewrap again with clear_disclosure_history
    let clear_request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, true, false);
    let after_remove = KvEncContent::new_unchecked(after_remove);
    let result = rewrap_kv_content(&after_remove, &clear_request);

    assert!(
        result.is_ok(),
        "rewrap with clear_disclosure_history must succeed: {:?}",
        result.err()
    );

    // The cleared content should not contain removed_recipients
    let cleared = result.unwrap();
    assert!(
        !cleared.contains("removed_recipients"),
        "cleared content must not contain removed_recipients disclosure history"
    );
}

#[test]
fn test_rewrap_kv_invalid_signature_error() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, kid);

    let encrypted = encrypt_kv_for_alice(&temp_dir, kid, &key_ctx);

    // Tamper the :SIG line
    let tampered = encrypted
        .lines()
        .map(|line| {
            if line.starts_with(":SIG ") {
                ":SIG TAMPERED_INVALID_SIGNATURE_DATA".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, false, false);
    let tampered = KvEncContent::new_unchecked(tampered);
    let result = rewrap_kv_content(&tampered, &request);

    assert!(
        result.is_err(),
        "rewrap_kv_document must fail on tampered signature"
    );
}

/// Extract disclosed flags from all KV entries in kv-enc content.
fn extract_disclosed_flags(content: &str) -> Vec<(String, bool)> {
    let doc = parse_kv_document(content).unwrap();
    doc.lines()
        .iter()
        .filter_map(|line| {
            if let KvEncLine::KV { key, token } = line {
                let entry: KvEntryValue = parse_kv_entry_token(token).unwrap();
                Some((key.clone(), entry.disclosed))
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn test_rewrap_kv_remove_recipient_sets_disclosed_true() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(&alice_kid));

    // Encrypt for alice and bob
    let encrypted = encrypt_kv_for_alice_and_bob(&temp_dir, &alice_kid, &bob_kid, &key_ctx);

    // Verify original entries have disclosed: false
    let original_flags = extract_disclosed_flags(&encrypted);
    assert!(
        original_flags.iter().all(|(_, d)| !d),
        "original entries must have disclosed: false"
    );

    // Setup workspace with only alice (bob removed)
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, &alice_kid);

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, false, false);
    let encrypted = KvEncContent::new_unchecked(encrypted);
    let rewrapped = rewrap_kv_content(&encrypted, &request).unwrap();

    // After removing bob, all entries must have disclosed: true
    let flags = extract_disclosed_flags(&rewrapped);
    assert!(
        !flags.is_empty(),
        "rewrapped content must contain KV entries"
    );
    for (key, disclosed) in &flags {
        assert!(
            *disclosed,
            "entry '{}' must have disclosed: true after recipient removal",
            key
        );
    }
}

#[test]
fn test_rewrap_kv_add_recipient_preserves_disclosed() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(&alice_kid));

    // Encrypt for alice only
    let encrypted = encrypt_kv_for_alice(&temp_dir, &alice_kid, &key_ctx);

    // Verify original entries have disclosed: false
    let original_flags = extract_disclosed_flags(&encrypted);
    assert!(
        original_flags.iter().all(|(_, d)| !d),
        "original entries must have disclosed: false"
    );

    // Setup workspace with both alice and bob as active members (adding bob)
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, &alice_kid);
    setup_workspace_members(&temp_dir, BOB_MEMBER_ID, &bob_kid);

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, false, false);
    let encrypted = KvEncContent::new_unchecked(encrypted);
    let rewrapped = rewrap_kv_content(&encrypted, &request).unwrap();

    // After adding bob (no removal), entries must preserve disclosed: false
    let flags = extract_disclosed_flags(&rewrapped);
    assert!(
        !flags.is_empty(),
        "rewrapped content must contain KV entries"
    );
    for (key, disclosed) in &flags {
        assert!(
            !*disclosed,
            "entry '{}' must have disclosed: false after add-only rewrap",
            key
        );
    }
}

#[test]
fn test_rewrap_kv_rotate_key_preserves_disclosed() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, kid);

    let encrypted = encrypt_kv_for_alice(&temp_dir, kid, &key_ctx);

    // Verify original entries have disclosed: false
    let original_flags = extract_disclosed_flags(&encrypted);
    assert!(
        original_flags.iter().all(|(_, d)| !d),
        "original entries must have disclosed: false"
    );

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), true, false, false);
    let encrypted = KvEncContent::new_unchecked(encrypted);
    let rewrapped = rewrap_kv_content(&encrypted, &request).unwrap();

    // After rotate-key without removal, entries must preserve disclosed: false
    let flags = extract_disclosed_flags(&rewrapped);
    assert!(!flags.is_empty(), "rotated content must contain KV entries");
    for (key, disclosed) in &flags {
        assert!(
            !*disclosed,
            "entry '{}' must have disclosed: false after rotate-key without removal",
            key
        );
    }
}

#[test]
fn test_rewrap_kv_remove_then_rotate_preserves_disclosed_true() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(&alice_kid));

    // Encrypt for alice and bob with two entries
    let keystore_root = temp_dir.path().join("keys");
    let alice_pub = load_public_key(&keystore_root, ALICE_MEMBER_ID, &alice_kid).unwrap();
    let bob_pub = load_public_key(&keystore_root, BOB_MEMBER_ID, &bob_kid).unwrap();
    let members = make_verified_members(&[alice_pub.clone(), bob_pub]);
    let kv_map = parse_dotenv("DATABASE_URL=postgres://localhost\nAPI_KEY=secret123\n").unwrap();
    let encrypted = encrypt_kv_document(
        &kv_map,
        &members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: &alice_kid,
            signer_pub: alice_pub,
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap();

    // Setup workspace with only alice (bob removed)
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, &alice_kid);

    // Step 1: Remove bob (sets disclosed: true on all entries) + rotate key
    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), true, false, false);
    let encrypted = KvEncContent::new_unchecked(encrypted);
    let rewrapped = rewrap_kv_content(&encrypted, &request).unwrap();

    // After remove + rotate, all entries must still have disclosed: true
    let flags = extract_disclosed_flags(&rewrapped);
    assert!(
        flags.len() >= 2,
        "rewrapped content must contain at least 2 KV entries, got {}",
        flags.len()
    );
    for (key, disclosed) in &flags {
        assert!(
            *disclosed,
            "entry '{}' must have disclosed: true after remove + rotate, but got false",
            key
        );
    }
}

#[test]
fn test_rewrap_kv_clear_disclosure_history_resets_disclosed_flags() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(&alice_kid));

    // Encrypt for alice and bob with two entries
    let keystore_root = temp_dir.path().join("keys");
    let alice_pub = load_public_key(&keystore_root, ALICE_MEMBER_ID, &alice_kid).unwrap();
    let bob_pub = load_public_key(&keystore_root, BOB_MEMBER_ID, &bob_kid).unwrap();
    let members = make_verified_members(&[alice_pub.clone(), bob_pub]);
    let kv_map = parse_dotenv("DATABASE_URL=postgres://localhost\nAPI_KEY=secret123\n").unwrap();
    let encrypted = encrypt_kv_document(
        &kv_map,
        &members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: &alice_kid,
            signer_pub: alice_pub,
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap();

    // Setup workspace with only alice (bob removed)
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, &alice_kid);

    // Step 1: Remove bob => disclosed: true on all entries, removed_recipients populated
    let remove_request =
        single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, false, false);
    let encrypted = KvEncContent::new_unchecked(encrypted);
    let after_remove = rewrap_kv_content(&encrypted, &remove_request).unwrap();

    // Verify disclosed: true after removal
    let flags_after_remove = extract_disclosed_flags(&after_remove);
    assert!(
        flags_after_remove.len() >= 2,
        "must have at least 2 entries"
    );
    for (key, disclosed) in &flags_after_remove {
        assert!(
            *disclosed,
            "entry '{}' must have disclosed: true after removal",
            key
        );
    }
    // Verify removed_recipients present by parsing the WRAP token
    let wrap_token_after_remove = after_remove
        .lines()
        .find(|l| l.starts_with(":WRAP "))
        .unwrap()
        .strip_prefix(":WRAP ")
        .unwrap();
    let wrap_after_remove: KvWrap = parse_kv_wrap_token(wrap_token_after_remove).unwrap();
    assert!(
        wrap_after_remove.removed_recipients.is_some(),
        "removed_recipients must be present after removal"
    );

    // Step 2: Clear disclosure history => disclosed: false, removed_recipients gone
    let clear_request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, true, false);
    let after_remove = KvEncContent::new_unchecked(after_remove);
    let after_clear = rewrap_kv_content(&after_remove, &clear_request).unwrap();

    // Verify all entries have disclosed: false (field omitted)
    let flags_after_clear = extract_disclosed_flags(&after_clear);
    assert!(
        flags_after_clear.len() >= 2,
        "must have at least 2 entries after clear"
    );
    for (key, disclosed) in &flags_after_clear {
        assert!(
            !*disclosed,
            "entry '{}' must have disclosed: false after clear_disclosure_history",
            key
        );
    }

    // Verify removed_recipients is gone by parsing the WRAP token
    let wrap_token_after_clear = after_clear
        .lines()
        .find(|l| l.starts_with(":WRAP "))
        .unwrap()
        .strip_prefix(":WRAP ")
        .unwrap();
    let wrap_after_clear: KvWrap = parse_kv_wrap_token(wrap_token_after_clear).unwrap();
    assert!(
        wrap_after_clear.removed_recipients.is_none(),
        "removed_recipients must be None after clear_disclosure_history"
    );

    // Verify the cleared content is still valid (parseable and verifiable)
    let doc = parse_kv_document(&after_clear);
    assert!(
        doc.is_ok(),
        "cleared content must be parseable: {:?}",
        doc.err()
    );
}
