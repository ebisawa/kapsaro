// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/rewrap/file module (file-enc document rewrap operations).

use crate::cli_common::{ALICE_MEMBER_ID, BOB_MEMBER_ID};
use crate::keygen_helpers::make_verified_members;
use crate::test_utils::{setup_member_key_context, setup_test_keystore_from_fixtures};
use secretenv::app::rewrap::execution::rewrap_file_content_with_request;
use secretenv::app::rewrap::types::SingleRewrapRequest;
use secretenv::feature::context::crypto::CryptoContext;
use secretenv::feature::encrypt::file::encrypt_file_document;
use secretenv::feature::envelope::signature::SigningContext;
use secretenv::format::content::FileEncContent;
use secretenv::io::keystore::storage::{list_kids, load_public_key};
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
) -> SingleRewrapRequest<'a> {
    SingleRewrapRequest {
        member_id: ALICE_MEMBER_ID,
        key_ctx,
        workspace_root,
        rotate_key,
        clear_disclosure_history,

        debug,
    }
}

/// Encrypt file content for alice (single recipient), returning the JSON string.
fn encrypt_file_for_alice(temp_dir: &TempDir, kid: &str, key_ctx: &CryptoContext) -> String {
    let keystore_root = temp_dir.path().join("keys");
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();
    let members = make_verified_members(&[public_key.clone()]);
    let content = b"test secret data";
    let recipient_ids = vec![ALICE_MEMBER_ID.to_string()];

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_ids,
        &members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
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
    let alice_pub = load_public_key(&keystore_root, ALICE_MEMBER_ID, alice_kid).unwrap();
    let bob_pub = load_public_key(&keystore_root, BOB_MEMBER_ID, bob_kid).unwrap();
    let members = make_verified_members(&[alice_pub.clone(), bob_pub]);
    let content = b"test secret data";
    let recipient_ids = vec![ALICE_MEMBER_ID.to_string(), BOB_MEMBER_ID.to_string()];

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_ids,
        &members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
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
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let alice_kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let alice_kid = alice_kids.first().unwrap().clone();

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
fn test_rewrap_file_add_recipient() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(&alice_kid));

    // Encrypt for alice only
    let json = encrypt_file_for_alice(&temp_dir, &alice_kid, &key_ctx);

    // Setup workspace with both alice and bob as active members
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, &alice_kid);
    setup_workspace_members(&temp_dir, BOB_MEMBER_ID, &bob_kid);

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, false, false);
    let result = rewrap_file_content_with_request(&FileEncContent::new_unchecked(json), &request);

    assert!(
        result.is_ok(),
        "rewrap adding recipient must succeed: {:?}",
        result.err()
    );

    // Parse the rewrapped document to verify bob was added
    let rewrapped = result.unwrap();
    let doc: secretenv::model::file_enc::FileEncDocument =
        serde_json::from_str(&rewrapped).unwrap();
    let recipient_ids: Vec<&str> = doc.protected.wrap.iter().map(|w| w.rid.as_str()).collect();
    assert!(
        recipient_ids.contains(&BOB_MEMBER_ID),
        "rewrapped document must include bob as a recipient, got: {:?}",
        recipient_ids
    );
    assert!(
        recipient_ids.contains(&ALICE_MEMBER_ID),
        "rewrapped document must still include alice as a recipient, got: {:?}",
        recipient_ids
    );
}

#[test]
fn test_rewrap_file_remove_recipient() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(&alice_kid));

    // Encrypt for alice and bob
    let json = encrypt_file_for_alice_and_bob(&temp_dir, &alice_kid, &bob_kid, &key_ctx);

    // Setup workspace with only alice (bob removed)
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, &alice_kid);

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, false, false);
    let result = rewrap_file_content_with_request(&FileEncContent::new_unchecked(json), &request);

    assert!(
        result.is_ok(),
        "rewrap removing recipient must succeed: {:?}",
        result.err()
    );

    // After removal, bob should not be in the wrap recipients
    let rewrapped = result.unwrap();
    let doc: secretenv::model::file_enc::FileEncDocument =
        serde_json::from_str(&rewrapped).unwrap();
    let recipient_ids: Vec<&str> = doc.protected.wrap.iter().map(|w| w.rid.as_str()).collect();
    assert!(
        !recipient_ids.contains(&BOB_MEMBER_ID),
        "rewrapped document must not include bob as a recipient, got: {:?}",
        recipient_ids
    );
    assert!(
        recipient_ids.contains(&ALICE_MEMBER_ID),
        "rewrapped document must still include alice, got: {:?}",
        recipient_ids
    );
}

#[test]
fn test_rewrap_file_rotate_key() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, kid);

    let json = encrypt_file_for_alice(&temp_dir, kid, &key_ctx);

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), true, false, false);
    let result =
        rewrap_file_content_with_request(&FileEncContent::new_unchecked(json.clone()), &request);

    assert!(
        result.is_ok(),
        "rewrap with rotate_key must succeed: {:?}",
        result.err()
    );

    // Rotated content must be valid JSON and wrap items should differ
    let rewrapped = result.unwrap();
    let original_doc: secretenv::model::file_enc::FileEncDocument =
        serde_json::from_str(&json).unwrap();
    let rotated_doc: secretenv::model::file_enc::FileEncDocument =
        serde_json::from_str(&rewrapped).unwrap();

    // The encrypted key material in wrap items should change after rotation
    let original_ct = &original_doc.protected.wrap[0].ct;
    let rotated_ct = &rotated_doc.protected.wrap[0].ct;
    assert_ne!(
        original_ct, rotated_ct,
        "wrap ct must change after key rotation"
    );
}

#[test]
fn test_rewrap_file_clear_disclosure_history() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(&alice_kid));

    // Encrypt for alice and bob
    let json = encrypt_file_for_alice_and_bob(&temp_dir, &alice_kid, &bob_kid, &key_ctx);

    // Setup workspace with only alice (bob removed) => removal creates disclosure history
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, &alice_kid);

    let remove_request =
        single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, false, false);
    let after_remove =
        rewrap_file_content_with_request(&FileEncContent::new_unchecked(json), &remove_request)
            .unwrap();

    // Verify disclosure history exists after removal
    let after_remove_doc: secretenv::model::file_enc::FileEncDocument =
        serde_json::from_str(&after_remove).unwrap();
    assert!(
        after_remove_doc.protected.removed_recipients.is_some(),
        "removed_recipients should exist after removing bob"
    );

    // Now rewrap again with clear_disclosure_history
    let clear_request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, true, false);
    let result = rewrap_file_content_with_request(
        &FileEncContent::new_unchecked(after_remove),
        &clear_request,
    );

    assert!(
        result.is_ok(),
        "rewrap with clear_disclosure_history must succeed: {:?}",
        result.err()
    );

    // After clearing, removed_recipients should be None
    let cleared = result.unwrap();
    let cleared_doc: secretenv::model::file_enc::FileEncDocument =
        serde_json::from_str(&cleared).unwrap();
    assert!(
        cleared_doc.protected.removed_recipients.is_none(),
        "removed_recipients must be cleared after clear_disclosure_history"
    );
}

#[test]
fn test_rewrap_file_preserves_payload() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, kid);

    let json = encrypt_file_for_alice(&temp_dir, kid, &key_ctx);

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, false, false);
    let result = rewrap_file_content_with_request(&FileEncContent::new_unchecked(json), &request);

    assert!(result.is_ok(), "rewrap must succeed: {:?}", result.err());

    let rewrapped = result.unwrap();
    let doc: secretenv::model::file_enc::FileEncDocument =
        serde_json::from_str(&rewrapped).unwrap();

    assert_eq!(
        doc.protected.format, "secretenv.file@3",
        "format field must be preserved as secretenv.file@3"
    );
}

#[test]
fn test_rewrap_file_requires_workspace() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));

    let json = encrypt_file_for_alice(&temp_dir, kid, &key_ctx);

    let request = single_rewrap_request(&key_ctx, None, false, false, false);
    let result = rewrap_file_content_with_request(&FileEncContent::new_unchecked(json), &request);

    assert!(
        result.is_err(),
        "rewrap_file_document must fail when workspace_root is None"
    );

    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("workspace"),
        "error message must mention workspace, got: {}",
        err_msg
    );
}
