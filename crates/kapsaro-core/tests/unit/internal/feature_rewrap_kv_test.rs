// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/rewrap/kv module (KV document rewrap operations).

use crate::feature::context::crypto::CryptoContext;
use crate::feature::context::crypto::SigningContext;
use crate::feature::kv::encrypt::encrypt_kv_document;
use crate::feature::rewrap::{rewrap_content, RewrapRequest};
use crate::format::content::{EncContent, KvEncContent};
use crate::format::kv::document::parse_kv_document;
use crate::format::kv::dotenv::parse_dotenv;
use crate::format::schema::document::{parse_kv_entry_token, parse_kv_wrap_token};
use crate::format::token::TokenCodec;
use crate::io::keystore::storage::{list_kids, load_public_key};
use crate::model::kv_enc::entry::KvEntryValue;
use crate::model::kv_enc::header::KvWrap;
use crate::model::kv_enc::line::KvEncLine;
use crate::test_utils::keygen_helpers::build_verified_recipient_keys;
use crate::test_utils::{
    save_active_public_key_to_workspace, setup_member_key_context,
    setup_test_keystore_from_fixtures, update_active_private_key_expires_at,
};
use crate::test_utils::{ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE};
use std::fs;
use tempfile::TempDir;

/// Create workspace members directory with the member's public key file.
fn setup_workspace_members(temp_dir: &TempDir, member_handle: &str, kid: &str) {
    let keystore_root = temp_dir.path().join("keys");
    let public_key = load_public_key(&keystore_root, member_handle, kid).unwrap();
    let members_dir = temp_dir.path().join("members/active");
    fs::create_dir_all(&members_dir).unwrap();
    fs::create_dir_all(temp_dir.path().join("members/incoming")).unwrap();
    let member_file = members_dir.join(format!("{}.json", member_handle));
    fs::write(
        &member_file,
        serde_json::to_string_pretty(&public_key).unwrap(),
    )
    .unwrap();
}

fn single_rewrap_request<'a>(
    key_ctx: &'a CryptoContext,
    workspace_root: Option<&std::path::Path>,
    rotate_key: bool,
    clear_disclosure_history: bool,
    debug: bool,
) -> RewrapRequest<'a> {
    let target_members = workspace_root
        .map(|workspace_root| {
            let public_keys =
                crate::io::workspace::members::load_active_member_files(workspace_root).unwrap();
            build_verified_recipient_keys(&public_keys)
        })
        .unwrap_or_default();
    RewrapRequest {
        member_handle: ALICE_MEMBER_HANDLE,
        key_ctx,
        target_members,
        rotate_key,
        clear_disclosure_history,
        debug,
    }
}

fn rewrap_kv_content(
    content: &KvEncContent,
    request: &RewrapRequest<'_>,
) -> kapsaro_core::Result<String> {
    rewrap_content(&EncContent::KvEnc(content.clone()), request)
}

fn parse_wrap_from_content(content: &str) -> KvWrap {
    let wrap_token = content
        .lines()
        .find(|line| line.starts_with(":WRAP "))
        .unwrap()
        .strip_prefix(":WRAP ")
        .unwrap();
    parse_kv_wrap_token(wrap_token).unwrap()
}

fn recipient_handles_from_wrap(wrap: &KvWrap) -> Vec<&str> {
    wrap.wrap
        .iter()
        .map(|item| item.recipient_handle.as_str())
        .collect()
}

fn removed_recipient_handles_from_wrap(wrap: &KvWrap) -> Vec<&str> {
    wrap.removed_recipients
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|item| item.recipient_handle.as_str())
        .collect()
}

/// Encrypt a simple KV document for alice (single recipient).
fn encrypt_kv_for_alice(temp_dir: &TempDir, kid: &str, key_ctx: &CryptoContext) -> String {
    let keystore_root = temp_dir.path().join("keys");
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, kid).unwrap();
    let members = build_verified_recipient_keys(std::slice::from_ref(&public_key));
    let kv_map = parse_dotenv("DATABASE_URL=postgres://localhost\n").unwrap();
    encrypt_kv_document(
        &kv_map,
        &members,
        &SigningContext {
            signing_key: key_ctx.signing_key(),
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
    let alice_pub = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, alice_kid).unwrap();
    let bob_pub = load_public_key(&keystore_root, BOB_MEMBER_HANDLE, bob_kid).unwrap();
    let members = build_verified_recipient_keys(&[alice_pub.clone(), bob_pub]);
    let kv_map = parse_dotenv("DATABASE_URL=postgres://localhost\n").unwrap();
    encrypt_kv_document(
        &kv_map,
        &members,
        &SigningContext {
            signing_key: key_ctx.signing_key(),
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
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let alice_kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let alice_kid = alice_kids.first().unwrap().clone();

    // Generate bob's keys in the same keystore
    let ssh_pub_content = std::fs::read_to_string(temp_dir.path().join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let ssh_priv = temp_dir.path().join(".ssh/test_ed25519");
    let (bob_private, bob_public) = crate::test_utils::keygen_helpers::keygen_test(
        BOB_MEMBER_HANDLE,
        &ssh_priv,
        &ssh_pub_content,
    )
    .unwrap();
    let bob_kid = bob_public.protected.kid.clone();
    let bob_private_doc = crate::test_utils::keygen_helpers::build_test_private_key(
        &bob_private,
        &bob_public.protected.subject_handle,
        &bob_public.protected.kid,
        &ssh_priv,
        &ssh_pub_content,
    )
    .unwrap();
    crate::io::keystore::storage::save_key_pair_atomic(
        &keystore_root,
        BOB_MEMBER_HANDLE,
        &bob_kid,
        &bob_private_doc,
        &bob_public,
    )
    .unwrap();

    (temp_dir, alice_kid, bob_kid)
}

#[test]
fn test_rewrap_kv_document_rotate_key() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, kid);

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
    let wrap = parse_wrap_from_content(&rewrapped);
    assert!(recipient_handles_from_wrap(&wrap).contains(&ALICE_MEMBER_HANDLE));
}

#[test]
fn test_rewrap_kv_succeeds_when_only_old_self_wrap_exists() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);

    let old_key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    let old_kid = old_key_ctx.kid().to_string();
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, &old_kid);
    let encrypted = encrypt_kv_for_alice(&temp_dir, &old_kid, &old_key_ctx);

    update_active_private_key_expires_at(
        temp_dir.path(),
        ALICE_MEMBER_HANDLE,
        "2028-01-01T00:00:00Z",
    );
    save_active_public_key_to_workspace(temp_dir.path(), temp_dir.path(), ALICE_MEMBER_HANDLE)
        .unwrap();

    let new_key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    let new_kid = new_key_ctx.kid().to_string();
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
    let wrap_data = parse_wrap_from_content(&rewrapped);
    let alice_wrap = wrap_data
        .wrap
        .iter()
        .find(|wrap| wrap.recipient_handle == ALICE_MEMBER_HANDLE)
        .unwrap();
    assert_eq!(alice_wrap.kid, new_kid);
}

#[test]
fn test_rewrap_kv_add_recipient() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&alice_kid));

    // Encrypt for alice only
    let encrypted = encrypt_kv_for_alice(&temp_dir, &alice_kid, &key_ctx);

    // Setup workspace with both alice and bob as active members
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, &alice_kid);
    setup_workspace_members(&temp_dir, BOB_MEMBER_HANDLE, &bob_kid);

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
    let wrap_data = parse_wrap_from_content(&rewrapped);
    let recipient_handles = recipient_handles_from_wrap(&wrap_data);
    assert!(
        recipient_handles.contains(&BOB_MEMBER_HANDLE),
        "rewrapped WRAP must include bob as a recipient, got: {:?}",
        recipient_handles
    );
    assert!(
        recipient_handles.contains(&ALICE_MEMBER_HANDLE),
        "rewrapped WRAP must still include alice as a recipient, got: {:?}",
        recipient_handles
    );
}

#[test]
fn test_rewrap_kv_remove_recipient_updates_wrap_and_history() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&alice_kid));
    let encrypted = encrypt_kv_for_alice_and_bob(&temp_dir, &alice_kid, &bob_kid, &key_ctx);
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, &alice_kid);

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, false, false);
    let encrypted = KvEncContent::new_unchecked(encrypted);
    let rewrapped = rewrap_kv_content(&encrypted, &request).unwrap();

    let wrap = parse_wrap_from_content(&rewrapped);
    let recipient_handles = recipient_handles_from_wrap(&wrap);
    assert!(recipient_handles.contains(&ALICE_MEMBER_HANDLE));
    assert!(!recipient_handles.contains(&BOB_MEMBER_HANDLE));

    let removed_recipient_handles = removed_recipient_handles_from_wrap(&wrap);
    assert!(removed_recipient_handles.contains(&BOB_MEMBER_HANDLE));
}

#[test]
fn test_rewrap_kv_clear_disclosure_history() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&alice_kid));

    // Encrypt for alice and bob
    let encrypted = encrypt_kv_for_alice_and_bob(&temp_dir, &alice_kid, &bob_kid, &key_ctx);

    // Setup workspace with only alice (bob removed) => removal creates disclosure history
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, &alice_kid);

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
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, kid);

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
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&alice_kid));

    // Encrypt for alice and bob
    let encrypted = encrypt_kv_for_alice_and_bob(&temp_dir, &alice_kid, &bob_kid, &key_ctx);

    // Verify original entries have disclosed: false
    let original_flags = extract_disclosed_flags(&encrypted);
    assert!(
        original_flags.iter().all(|(_, d)| !d),
        "original entries must have disclosed: false"
    );

    // Setup workspace with only alice (bob removed)
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, &alice_kid);

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
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&alice_kid));

    // Encrypt for alice only
    let encrypted = encrypt_kv_for_alice(&temp_dir, &alice_kid, &key_ctx);

    // Verify original entries have disclosed: false
    let original_flags = extract_disclosed_flags(&encrypted);
    assert!(
        original_flags.iter().all(|(_, d)| !d),
        "original entries must have disclosed: false"
    );

    // Setup workspace with both alice and bob as active members (adding bob)
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, &alice_kid);
    setup_workspace_members(&temp_dir, BOB_MEMBER_HANDLE, &bob_kid);

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
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, kid);

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
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&alice_kid));

    // Encrypt for alice and bob with two entries
    let keystore_root = temp_dir.path().join("keys");
    let alice_pub = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &alice_kid).unwrap();
    let bob_pub = load_public_key(&keystore_root, BOB_MEMBER_HANDLE, &bob_kid).unwrap();
    let members = build_verified_recipient_keys(&[alice_pub.clone(), bob_pub]);
    let kv_map = parse_dotenv("DATABASE_URL=postgres://localhost\nAPI_KEY=secret123\n").unwrap();
    let encrypted = encrypt_kv_document(
        &kv_map,
        &members,
        &SigningContext {
            signing_key: key_ctx.signing_key(),
            signer_kid: &alice_kid,
            signer_pub: alice_pub,
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap();

    // Setup workspace with only alice (bob removed)
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, &alice_kid);

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
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&alice_kid));

    // Encrypt for alice and bob with two entries
    let keystore_root = temp_dir.path().join("keys");
    let alice_pub = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &alice_kid).unwrap();
    let bob_pub = load_public_key(&keystore_root, BOB_MEMBER_HANDLE, &bob_kid).unwrap();
    let members = build_verified_recipient_keys(&[alice_pub.clone(), bob_pub]);
    let kv_map = parse_dotenv("DATABASE_URL=postgres://localhost\nAPI_KEY=secret123\n").unwrap();
    let encrypted = encrypt_kv_document(
        &kv_map,
        &members,
        &SigningContext {
            signing_key: key_ctx.signing_key(),
            signer_kid: &alice_kid,
            signer_pub: alice_pub,
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap();

    // Setup workspace with only alice (bob removed)
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, &alice_kid);

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
    let wrap_after_remove = parse_wrap_from_content(&after_remove);
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
    let wrap_after_clear = parse_wrap_from_content(&after_clear);
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
