// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for core/usecase/rewrap module
//!
//! Tests for file-enc rewrap, including signature verification at entry.

use crate::keygen_helpers::make_verified_members;
use crate::test_utils::ALICE_MEMBER_ID;
use crate::test_utils::{setup_member_key_context, setup_test_keystore_from_fixtures};
use base64::Engine;
use secretenv::feature::encrypt::file::encrypt_file_document;
use secretenv::feature::envelope::signature::SigningContext;
use secretenv::feature::rewrap::{rewrap_content, RewrapRequest};
use secretenv::format::content::{EncryptedContent, FileEncContent};
use secretenv::io::keystore::storage::{list_kids, load_public_key};
use std::fs;
use tempfile::TempDir;

/// Create workspace members directory with the member's public key file.
///
/// The rewrap flow calls `list_active_member_ids(workspace_root)` to determine target recipients,
/// so the workspace must have a `members/active/<member_id>.json` file.
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
    key_ctx: &'a secretenv::feature::context::crypto::CryptoContext,
    workspace_root: Option<&'a std::path::Path>,
    debug: bool,
) -> RewrapRequest<'a> {
    RewrapRequest {
        member_id: ALICE_MEMBER_ID,
        key_ctx,
        workspace_root,
        target_members: None,
        rotate_key: false,
        clear_disclosure_history: false,

        debug,
    }
}

fn rewrap_file_content(
    content: &FileEncContent,
    request: &RewrapRequest<'_>,
) -> secretenv::Result<String> {
    rewrap_content(&EncryptedContent::FileEnc(content.clone()), request)
}

#[test]
fn test_rewrap_file_flow_rejects_invalid_signature() {
    // Create valid file-enc content, then tamper the signature so verification fails.
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));

    let content = b"secret";
    let recipient_ids = vec![ALICE_MEMBER_ID.to_string()];
    let members = make_verified_members(std::slice::from_ref(&public_key));

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

    let mut file_enc_doc_tampered = file_enc_doc.clone();
    file_enc_doc_tampered.signature.sig =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"tampered_signature");
    let json = serde_json::to_string_pretty(&file_enc_doc_tampered).unwrap();

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false);
    let result = rewrap_file_content(&FileEncContent::new_unchecked(json), &request);

    assert!(
        result.is_err(),
        "rewrap_file_document must fail on invalid signature"
    );
}

#[test]
fn test_rewrap_file_flow_succeeds_with_valid_signature() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, kid);

    let content = b"secret";
    let recipient_ids = vec![ALICE_MEMBER_ID.to_string()];
    let members = make_verified_members(std::slice::from_ref(&public_key));

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

    let json = serde_json::to_string_pretty(&file_enc_doc).unwrap();
    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false);
    let result = rewrap_file_content(&FileEncContent::new_unchecked(json), &request);

    assert!(
        result.is_ok(),
        "rewrap_file_document must succeed with valid signature: {:?}",
        result.err()
    );
}
