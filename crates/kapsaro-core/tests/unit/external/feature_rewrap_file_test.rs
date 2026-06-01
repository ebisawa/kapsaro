// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/rewrap/file module (file-enc document rewrap operations).

use crate::keygen_helpers::build_verified_recipient_keys;
use crate::test_utils::{
    save_active_public_key_to_workspace, setup_member_key_context,
    setup_test_keystore_from_fixtures, update_active_private_key_expires_at,
};
use crate::test_utils::{ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE};
use kapsaro_core::cli_api::test_support::domain::public_key::VerifiedRecipientKey;
use kapsaro_core::cli_api::test_support::operations::context::crypto::CryptoContext;
use kapsaro_core::cli_api::test_support::operations::context::crypto::SigningContext;
use kapsaro_core::cli_api::test_support::operations::encrypt::file::encrypt_file_document;
use kapsaro_core::cli_api::test_support::operations::rewrap::{rewrap_content, RewrapRequest};
use kapsaro_core::cli_api::test_support::storage::keystore::storage::{list_kids, load_public_key};
use kapsaro_core::cli_api::test_support::wire::content::{EncContent, FileEncContent};
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
    target_members: Vec<VerifiedRecipientKey>,
    rotate_key: bool,
    clear_disclosure_history: bool,
    debug: bool,
) -> RewrapRequest<'a> {
    RewrapRequest {
        member_handle: ALICE_MEMBER_HANDLE,
        key_ctx,
        target_members,
        rotate_key,
        clear_disclosure_history,
        debug,
    }
}

fn build_rewrap_targets(temp_dir: &TempDir, members: &[(&str, &str)]) -> Vec<VerifiedRecipientKey> {
    let keystore_root = temp_dir.path().join("keys");
    let public_keys = members
        .iter()
        .map(|(member_handle, kid)| load_public_key(&keystore_root, member_handle, kid).unwrap())
        .collect::<Vec<_>>();
    build_verified_recipient_keys(&public_keys)
}

fn rewrap_file_content(
    content: &FileEncContent,
    request: &RewrapRequest<'_>,
) -> kapsaro_core::Result<String> {
    rewrap_content(&EncContent::FileEnc(content.clone()), request)
}

/// Encrypt file content for alice (single recipient), returning the JSON string.
fn encrypt_file_for_alice(temp_dir: &TempDir, kid: &str, key_ctx: &CryptoContext) -> String {
    let keystore_root = temp_dir.path().join("keys");
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, kid).unwrap();
    let members = build_verified_recipient_keys(std::slice::from_ref(&public_key));
    let content = b"test secret data";
    let recipient_handles = vec![ALICE_MEMBER_HANDLE.to_string()];

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_handles,
        &members,
        &SigningContext {
            signing_key: key_ctx.signing_key(),
            signer_kid: kid,
            signer_pub: public_key,
            debug: false,
        },
    )
    .unwrap();

    serde_json::to_string_pretty(&file_enc_doc).unwrap()
}

/// Encrypt file content for alice and bob (two recipients), returning the JSON string.
fn encrypt_file_for_alice_and_bob(
    temp_dir: &TempDir,
    alice_kid: &str,
    bob_kid: &str,
    key_ctx: &CryptoContext,
) -> String {
    let keystore_root = temp_dir.path().join("keys");
    let alice_pub = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, alice_kid).unwrap();
    let bob_pub = load_public_key(&keystore_root, BOB_MEMBER_HANDLE, bob_kid).unwrap();
    let members = build_verified_recipient_keys(&[alice_pub.clone(), bob_pub]);
    let content = b"test secret data";
    let recipient_handles = vec![
        ALICE_MEMBER_HANDLE.to_string(),
        BOB_MEMBER_HANDLE.to_string(),
    ];

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_handles,
        &members,
        &SigningContext {
            signing_key: key_ctx.signing_key(),
            signer_kid: alice_kid,
            signer_pub: alice_pub,
            debug: false,
        },
    )
    .unwrap();

    serde_json::to_string_pretty(&file_enc_doc).unwrap()
}

/// Setup a two-member keystore (alice + bob) in one TempDir.
///
/// Returns (temp_dir, alice_kid, bob_kid).
fn setup_two_member_keystore() -> (TempDir, String, String) {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let alice_kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let alice_kid = alice_kids.first().unwrap().clone();

    let ssh_pub_content = std::fs::read_to_string(temp_dir.path().join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let ssh_priv = temp_dir.path().join(".ssh/test_ed25519");
    let (bob_private, bob_public) =
        crate::keygen_helpers::keygen_test(BOB_MEMBER_HANDLE, &ssh_priv, &ssh_pub_content).unwrap();
    let bob_kid = bob_public.protected.kid.clone();
    let bob_private_doc = crate::keygen_helpers::build_test_private_key(
        &bob_private,
        &bob_public.protected.subject_handle,
        &bob_public.protected.kid,
        &ssh_priv,
        &ssh_pub_content,
    )
    .unwrap();
    kapsaro_core::cli_api::test_support::storage::keystore::storage::save_key_pair_atomic(
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
fn test_rewrap_file_succeeds_when_only_old_self_wrap_exists() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let old_key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    let old_kid = old_key_ctx.kid().to_string();
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, &old_kid);
    let json = encrypt_file_for_alice(&temp_dir, &old_kid, &old_key_ctx);

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
    assert!(load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &new_kid).is_ok());

    let target_members = build_rewrap_targets(&temp_dir, &[(ALICE_MEMBER_HANDLE, &new_kid)]);
    let request = single_rewrap_request(&new_key_ctx, target_members, false, false, false);
    let result = rewrap_file_content(&FileEncContent::new_unchecked(json), &request);

    assert!(
        result.is_ok(),
        "rewrap with only old self wrap must succeed: {:?}",
        result.err()
    );

    let rewrapped = result.unwrap();
    let doc: kapsaro_core::cli_api::test_support::domain::file_enc::FileEncDocument =
        serde_json::from_str(&rewrapped).unwrap();
    let alice_wrap = doc
        .protected
        .wrap
        .iter()
        .find(|wrap| wrap.recipient_handle == ALICE_MEMBER_HANDLE)
        .unwrap();
    assert_eq!(alice_wrap.kid, new_kid);
    assert_eq!(doc.signature.kid, new_key_ctx.kid().to_string());
}

#[test]
fn test_rewrap_file_clear_disclosure_history() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&alice_kid));

    // Encrypt for alice and bob
    let json = encrypt_file_for_alice_and_bob(&temp_dir, &alice_kid, &bob_kid, &key_ctx);

    // Setup workspace with only alice (bob removed) => removal creates disclosure history
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, &alice_kid);

    let target_members = build_rewrap_targets(&temp_dir, &[(ALICE_MEMBER_HANDLE, &alice_kid)]);
    let remove_request =
        single_rewrap_request(&key_ctx, target_members.clone(), false, false, false);
    let after_remove =
        rewrap_file_content(&FileEncContent::new_unchecked(json), &remove_request).unwrap();

    // Verify disclosure history exists after removal
    let after_remove_doc: kapsaro_core::cli_api::test_support::domain::file_enc::FileEncDocument =
        serde_json::from_str(&after_remove).unwrap();
    assert!(
        after_remove_doc.protected.removed_recipients.is_some(),
        "removed_recipients should exist after removing bob"
    );

    // Now rewrap again with clear_disclosure_history
    let clear_request = single_rewrap_request(&key_ctx, target_members, false, true, false);
    let result = rewrap_file_content(&FileEncContent::new_unchecked(after_remove), &clear_request);

    assert!(
        result.is_ok(),
        "rewrap with clear_disclosure_history must succeed: {:?}",
        result.err()
    );

    // After clearing, removed_recipients should be None
    let cleared = result.unwrap();
    let cleared_doc: kapsaro_core::cli_api::test_support::domain::file_enc::FileEncDocument =
        serde_json::from_str(&cleared).unwrap();
    assert!(
        cleared_doc.protected.removed_recipients.is_none(),
        "removed_recipients must be cleared after clear_disclosure_history"
    );
}

#[test]
fn test_rewrap_file_uses_fixed_target_member_snapshot() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));

    let json = encrypt_file_for_alice(&temp_dir, kid, &key_ctx);

    let target_members = build_rewrap_targets(&temp_dir, &[(ALICE_MEMBER_HANDLE, kid)]);
    let request = single_rewrap_request(&key_ctx, target_members, false, false, false);
    let result = rewrap_file_content(&FileEncContent::new_unchecked(json), &request);

    assert!(
        result.is_ok(),
        "rewrap_file_document should use the supplied target member snapshot: {:?}",
        result.err()
    );
}
