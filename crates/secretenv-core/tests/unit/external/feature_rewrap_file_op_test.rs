// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/rewrap/file_op module (file-enc rewrap operations).
//!
//! Tests rotate, add-recipient, and remove-recipient via the app-level
//! rewrap API since `file_op` is `pub(crate)`.

use crate::keygen_helpers::build_verified_recipient_keys;
use crate::test_utils::{setup_member_key_context, setup_test_keystore_from_fixtures};
use crate::test_utils::{ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE, CAROL_MEMBER_HANDLE};
use secretenv_core::cli_api::test_support::domain::file_enc::FileEncDocument;
use secretenv_core::cli_api::test_support::operations::context::crypto::CryptoContext;
use secretenv_core::cli_api::test_support::operations::decrypt::file::decrypt_file_document;
use secretenv_core::cli_api::test_support::operations::encrypt::file::encrypt_file_document;
use secretenv_core::cli_api::test_support::operations::envelope::signature::sign_file_document;
use secretenv_core::cli_api::test_support::operations::envelope::signature::SigningContext;
use secretenv_core::cli_api::test_support::operations::rewrap::{rewrap_content, RewrapRequest};
use secretenv_core::cli_api::test_support::operations::verify::file::verify_file_document;
use secretenv_core::cli_api::test_support::primitives::types::keys::MasterKey;
use secretenv_core::cli_api::test_support::storage::keystore::storage::save_key_pair_atomic;
use secretenv_core::cli_api::test_support::storage::keystore::storage::{
    list_kids, load_public_key,
};
use secretenv_core::cli_api::test_support::wire::content::{EncContent, FileEncContent};
use std::fs;
use tempfile::TempDir;

// ============================================================================
// Helper functions
// ============================================================================

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
    workspace_root: Option<&'a std::path::Path>,
    rotate_key: bool,
    clear_disclosure_history: bool,
    debug: bool,
) -> RewrapRequest<'a> {
    RewrapRequest {
        member_handle: ALICE_MEMBER_HANDLE,
        key_ctx,
        workspace_root,
        target_members: None,
        rotate_key,
        clear_disclosure_history,

        debug,
    }
}

fn rewrap_file_content(
    content: &FileEncContent,
    request: &RewrapRequest<'_>,
) -> secretenv_core::Result<String> {
    rewrap_content(&EncContent::FileEnc(content.clone()), request)
}

fn add_member_to_keystore(temp_dir: &TempDir, member_handle: &str) -> String {
    let keystore_root = temp_dir.path().join("keys");
    let ssh_pub_content = std::fs::read_to_string(temp_dir.path().join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let ssh_priv = temp_dir.path().join(".ssh/test_ed25519");
    let (bob_private, bob_public) =
        crate::keygen_helpers::keygen_test(member_handle, &ssh_priv, &ssh_pub_content).unwrap();
    let bob_kid = bob_public.protected.kid.clone();
    let bob_private_doc = crate::keygen_helpers::build_test_private_key(
        &bob_private,
        &bob_public.protected.subject_handle,
        &bob_public.protected.kid,
        &ssh_priv,
        &ssh_pub_content,
    )
    .unwrap();
    save_key_pair_atomic(
        &keystore_root,
        member_handle,
        &bob_kid,
        &bob_private_doc,
        &bob_public,
    )
    .unwrap();
    bob_kid
}

/// Setup a two-member keystore (alice + bob) in one TempDir.
///
/// Returns (temp_dir, alice_kid, bob_kid).
fn setup_two_member_keystore() -> (TempDir, String, String) {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let alice_kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let alice_kid = alice_kids.first().unwrap().clone();
    let bob_kid = add_member_to_keystore(&temp_dir, BOB_MEMBER_HANDLE);

    (temp_dir, alice_kid, bob_kid)
}

/// Setup a three-member keystore (alice + bob + carol) in one TempDir.
///
/// Returns (temp_dir, alice_kid, bob_kid, carol_kid).
fn setup_three_member_keystore() -> (TempDir, String, String, String) {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let carol_kid = add_member_to_keystore(&temp_dir, CAROL_MEMBER_HANDLE);
    (temp_dir, alice_kid, bob_kid, carol_kid)
}

/// Encrypt file content for alice only.
fn encrypt_file_for_alice(
    temp_dir: &TempDir,
    kid: &str,
    key_ctx: &CryptoContext,
) -> FileEncDocument {
    let keystore_root = temp_dir.path().join("keys");
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, kid).unwrap();
    let members = build_verified_recipient_keys(std::slice::from_ref(&public_key));
    let content = b"secret-file-content";
    let recipients = vec![ALICE_MEMBER_HANDLE.to_string()];

    encrypt_file_document(
        content,
        &recipients,
        &members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: kid,
            signer_pub: public_key.clone(),
            debug: false,
        },
    )
    .unwrap()
}

fn resign_with_invalid_key_possession(
    temp_dir: &TempDir,
    kid: &str,
    key_ctx: &CryptoContext,
    mut document: FileEncDocument,
) -> FileEncDocument {
    let keystore_root = temp_dir.path().join("keys");
    let signer_pub = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, kid).unwrap();
    let wrong_content_key = MasterKey::new([0xA5; 32]);
    document.signature = sign_file_document(
        &document.protected,
        &wrong_content_key,
        &key_ctx.signing_key,
        kid,
        signer_pub,
        false,
    )
    .unwrap();
    document
}

/// Encrypt file content for alice and bob.
fn encrypt_file_for_alice_and_bob(
    temp_dir: &TempDir,
    alice_kid: &str,
    bob_kid: &str,
    key_ctx: &CryptoContext,
) -> FileEncDocument {
    let keystore_root = temp_dir.path().join("keys");
    let alice_pub = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, alice_kid).unwrap();
    let bob_pub = load_public_key(&keystore_root, BOB_MEMBER_HANDLE, bob_kid).unwrap();
    let members = build_verified_recipient_keys(&[alice_pub.clone(), bob_pub]);
    let content = b"secret-file-content";
    let recipients = vec![
        ALICE_MEMBER_HANDLE.to_string(),
        BOB_MEMBER_HANDLE.to_string(),
    ];

    encrypt_file_document(
        content,
        &recipients,
        &members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: alice_kid,
            signer_pub: alice_pub,
            debug: false,
        },
    )
    .unwrap()
}

// ============================================================================
// Tests: Key rotation via rewrap_file_document
// ============================================================================

#[test]
fn test_rotate_file_key_changes_content() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, kid);

    let doc = encrypt_file_for_alice(&temp_dir, kid, &key_ctx);
    let original_json = serde_json::to_string_pretty(&doc).unwrap();

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), true, false, false);
    let rewrapped_json = rewrap_file_content(
        &FileEncContent::new_unchecked(original_json.clone()),
        &request,
    )
    .unwrap();

    // Parse both documents to compare encrypted content
    let original_doc: FileEncDocument = serde_json::from_str(&original_json).unwrap();
    let rewrapped_doc: FileEncDocument = serde_json::from_str(&rewrapped_json).unwrap();

    assert_ne!(
        original_doc.protected.payload.encrypted.ct, rewrapped_doc.protected.payload.encrypted.ct,
        "ciphertext must change after key rotation"
    );
}

#[test]
fn test_rotate_file_key_preserves_decryptability() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, kid);

    let doc = encrypt_file_for_alice(&temp_dir, kid, &key_ctx);
    let original_json = serde_json::to_string_pretty(&doc).unwrap();

    // Rewrap with rotation
    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), true, false, false);
    let rewrapped_json = rewrap_file_content(
        &FileEncContent::new_unchecked(original_json.clone()),
        &request,
    )
    .unwrap();

    // Verify and decrypt the rewrapped document
    let rewrapped_doc: FileEncDocument = serde_json::from_str(&rewrapped_json).unwrap();
    let verified = verify_file_document(&rewrapped_doc, false).unwrap();
    let decrypted = decrypt_file_document(
        &verified,
        ALICE_MEMBER_HANDLE,
        kid,
        &key_ctx.private_key,
        false,
    )
    .unwrap();

    assert_eq!(
        decrypted.as_slice(),
        b"secret-file-content",
        "decrypted content must match original after key rotation"
    );
}

#[test]
fn test_rotate_file_key_updates_wrap() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, kid);

    let doc = encrypt_file_for_alice(&temp_dir, kid, &key_ctx);
    let original_json = serde_json::to_string_pretty(&doc).unwrap();

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), true, false, false);
    let rewrapped_json = rewrap_file_content(
        &FileEncContent::new_unchecked(original_json.clone()),
        &request,
    )
    .unwrap();

    let original_doc: FileEncDocument = serde_json::from_str(&original_json).unwrap();
    let rewrapped_doc: FileEncDocument = serde_json::from_str(&rewrapped_json).unwrap();

    // WRAP data (ct field) must change because a new content key was generated
    let original_ct = &original_doc.protected.wrap[0].ct;
    let rewrapped_ct = &rewrapped_doc.protected.wrap[0].ct;
    assert_ne!(
        original_ct, rewrapped_ct,
        "wrap ct must change after key rotation"
    );
}

#[test]
fn test_rewrap_file_rejects_invalid_key_possession_without_rotation() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, kid);

    let document = encrypt_file_for_alice(&temp_dir, kid, &key_ctx);
    let document = resign_with_invalid_key_possession(&temp_dir, kid, &key_ctx, document);
    let verified = verify_file_document(&document, false)
        .expect("tampered proof fixture must keep a valid Ed25519 signature");

    assert!(
        decrypt_file_document(
            &verified,
            ALICE_MEMBER_HANDLE,
            kid,
            &key_ctx.private_key,
            false,
        )
        .is_err(),
        "fixture must be rejected by normal decrypt"
    );

    let json = serde_json::to_string_pretty(&document).unwrap();
    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, false, false);
    let result = rewrap_file_content(&FileEncContent::new_unchecked(json), &request);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("E_KEY_POSSESSION_MAC_INVALID"));
}

#[test]
fn test_rotate_file_key_rejects_invalid_key_possession() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, kid);

    let document = encrypt_file_for_alice(&temp_dir, kid, &key_ctx);
    let document = resign_with_invalid_key_possession(&temp_dir, kid, &key_ctx, document);
    let json = serde_json::to_string_pretty(&document).unwrap();

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), true, false, false);
    let result = rewrap_file_content(&FileEncContent::new_unchecked(json), &request);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("E_KEY_POSSESSION_MAC_INVALID"));
}

// ============================================================================
// Tests: Recipient management via rewrap_file_document
// ============================================================================

#[test]
fn test_add_file_recipient_via_rewrap() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&alice_kid));

    // Encrypt for alice only
    let doc = encrypt_file_for_alice(&temp_dir, &alice_kid, &key_ctx);
    let json = serde_json::to_string_pretty(&doc).unwrap();

    // Setup workspace with both alice and bob as active members
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, &alice_kid);
    setup_workspace_members(&temp_dir, BOB_MEMBER_HANDLE, &bob_kid);

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, false, false);
    let rewrapped_json =
        rewrap_file_content(&FileEncContent::new_unchecked(json), &request).unwrap();

    let rewrapped_doc: FileEncDocument = serde_json::from_str(&rewrapped_json).unwrap();
    let recipient_handles: Vec<&str> = rewrapped_doc
        .protected
        .wrap
        .iter()
        .map(|w| w.recipient_handle.as_str())
        .collect();

    assert!(
        recipient_handles.contains(&ALICE_MEMBER_HANDLE),
        "rewrapped file must still include alice, got: {:?}",
        recipient_handles
    );
    assert!(
        recipient_handles.contains(&BOB_MEMBER_HANDLE),
        "rewrapped file must include bob after adding, got: {:?}",
        recipient_handles
    );
}

#[test]
fn test_add_file_recipient_already_exists_noop() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, kid);

    let doc = encrypt_file_for_alice(&temp_dir, kid, &key_ctx);
    let json = serde_json::to_string_pretty(&doc).unwrap();

    // Rewrap when all recipients already present (alice is both in doc and workspace)
    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, false, false);
    let result = rewrap_file_content(&FileEncContent::new_unchecked(json), &request);

    assert!(
        result.is_ok(),
        "rewrap with no recipient changes must succeed: {:?}",
        result.err()
    );

    let rewrapped_doc: FileEncDocument = serde_json::from_str(&result.unwrap()).unwrap();
    assert_eq!(
        rewrapped_doc.protected.wrap.len(),
        1,
        "wrap count must remain 1 when no recipients added or removed"
    );
}

#[test]
fn test_remove_file_recipient_via_rewrap() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&alice_kid));

    // Encrypt for alice and bob
    let doc = encrypt_file_for_alice_and_bob(&temp_dir, &alice_kid, &bob_kid, &key_ctx);
    let json = serde_json::to_string_pretty(&doc).unwrap();

    // Setup workspace with only alice (bob removed from workspace)
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, &alice_kid);

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, false, false);
    let rewrapped_json =
        rewrap_file_content(&FileEncContent::new_unchecked(json), &request).unwrap();

    let rewrapped_doc: FileEncDocument = serde_json::from_str(&rewrapped_json).unwrap();
    let recipient_handles: Vec<&str> = rewrapped_doc
        .protected
        .wrap
        .iter()
        .map(|w| w.recipient_handle.as_str())
        .collect();

    assert!(
        recipient_handles.contains(&ALICE_MEMBER_HANDLE),
        "alice must remain after bob's removal, got: {:?}",
        recipient_handles
    );
    assert!(
        !recipient_handles.contains(&BOB_MEMBER_HANDLE),
        "bob must be removed from recipients, got: {:?}",
        recipient_handles
    );
}

#[test]
fn test_replace_file_recipient_wraps_added_member_with_rotated_key() {
    let (temp_dir, alice_kid, bob_kid, carol_kid) = setup_three_member_keystore();
    let alice_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&alice_kid));
    let carol_ctx = setup_member_key_context(&temp_dir, CAROL_MEMBER_HANDLE, Some(&carol_kid));

    let doc = encrypt_file_for_alice_and_bob(&temp_dir, &alice_kid, &bob_kid, &alice_ctx);
    let json = serde_json::to_string_pretty(&doc).unwrap();

    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, &alice_kid);
    setup_workspace_members(&temp_dir, CAROL_MEMBER_HANDLE, &carol_kid);

    let request = single_rewrap_request(&alice_ctx, Some(temp_dir.path()), false, false, false);
    let rewrapped_json =
        rewrap_file_content(&FileEncContent::new_unchecked(json), &request).unwrap();
    let rewrapped_doc: FileEncDocument = serde_json::from_str(&rewrapped_json).unwrap();
    let verified = verify_file_document(&rewrapped_doc, false).unwrap();

    let decrypted = decrypt_file_document(
        &verified,
        CAROL_MEMBER_HANDLE,
        &carol_kid,
        &carol_ctx.private_key,
        false,
    )
    .unwrap();

    assert_eq!(decrypted.as_slice(), b"secret-file-content");
    assert!(rewrapped_doc
        .protected
        .wrap
        .iter()
        .any(|wrap| wrap.recipient_handle == CAROL_MEMBER_HANDLE));
}

#[test]
fn test_remove_file_recipient_adds_disclosure() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&alice_kid));

    // Encrypt for alice and bob
    let doc = encrypt_file_for_alice_and_bob(&temp_dir, &alice_kid, &bob_kid, &key_ctx);
    let json = serde_json::to_string_pretty(&doc).unwrap();

    // Setup workspace with only alice (bob removed)
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, &alice_kid);

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false, false, false);
    let rewrapped_json =
        rewrap_file_content(&FileEncContent::new_unchecked(json), &request).unwrap();

    // The output JSON must contain removed_recipients disclosure history
    assert!(
        rewrapped_json.contains("removed_recipients"),
        "rewrapped output must contain removed_recipients disclosure history"
    );

    let rewrapped_doc: FileEncDocument = serde_json::from_str(&rewrapped_json).unwrap();
    let removed = rewrapped_doc.protected.removed_recipients.as_ref();
    assert!(
        removed.is_some(),
        "removed_recipients field must be present after removal"
    );

    let removed = removed.unwrap();
    let removed_ids: Vec<&str> = removed
        .iter()
        .map(|r| r.recipient_handle.as_str())
        .collect();
    assert!(
        removed_ids.contains(&BOB_MEMBER_HANDLE),
        "bob must appear in removed_recipients, got: {:?}",
        removed_ids
    );
}

#[test]
fn test_rewrap_file_roundtrip_with_rotation() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));
    setup_workspace_members(&temp_dir, ALICE_MEMBER_HANDLE, kid);

    // Encrypt
    let doc = encrypt_file_for_alice(&temp_dir, kid, &key_ctx);
    let original_json = serde_json::to_string_pretty(&doc).unwrap();

    // Rewrap with rotation
    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), true, false, false);
    let rewrapped_json =
        rewrap_file_content(&FileEncContent::new_unchecked(original_json), &request).unwrap();

    // Output must be valid JSON parseable as FileEncDocument
    let parsed: Result<FileEncDocument, _> = serde_json::from_str(&rewrapped_json);
    assert!(
        parsed.is_ok(),
        "rewrapped output must be valid FileEncDocument JSON: {:?}",
        parsed.err()
    );

    // Verify signature on rewrapped document
    let rewrapped_doc = parsed.unwrap();
    let verified = verify_file_document(&rewrapped_doc, false);
    assert!(
        verified.is_ok(),
        "rewrapped document must pass signature verification: {:?}",
        verified.err()
    );
}
