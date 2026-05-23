// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for core/usecase/rewrap module
//!
//! Tests for file-enc rewrap, including signature verification at entry.

use crate::keygen_helpers::build_verified_recipient_keys;
use crate::test_utils::ALICE_MEMBER_HANDLE;
use crate::test_utils::{setup_member_key_context, setup_test_keystore_from_fixtures};
use secretenv_core::cli_api::test_support::helpers::codec::base64_public::encode_base64url_nopad;
use secretenv_core::cli_api::test_support::operations::encrypt::file::encrypt_file_document;
use secretenv_core::cli_api::test_support::operations::envelope::signature::SigningContext;
use secretenv_core::cli_api::test_support::operations::rewrap::{rewrap_content, RewrapRequest};
use secretenv_core::cli_api::test_support::storage::keystore::storage::{
    list_kids, load_public_key,
};
use secretenv_core::cli_api::test_support::wire::content::{EncContent, FileEncContent};

fn single_rewrap_request<'a>(
    key_ctx: &'a secretenv_core::cli_api::test_support::operations::context::crypto::CryptoContext,
    workspace_root: Option<&'a std::path::Path>,
    debug: bool,
) -> RewrapRequest<'a> {
    RewrapRequest {
        member_handle: ALICE_MEMBER_HANDLE,
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
) -> secretenv_core::Result<String> {
    rewrap_content(&EncContent::FileEnc(content.clone()), request)
}

#[test]
fn test_rewrap_file_operation_rejects_invalid_signature() {
    // Create valid file-enc content, then tamper the signature so verification fails.
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_HANDLE).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, kid).unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(kid));

    let content = b"secret";
    let recipient_handles = vec![ALICE_MEMBER_HANDLE.to_string()];
    let members = build_verified_recipient_keys(std::slice::from_ref(&public_key));

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_handles,
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
    file_enc_doc_tampered.signature.sig = encode_base64url_nopad(b"tampered_signature");
    let json = serde_json::to_string_pretty(&file_enc_doc_tampered).unwrap();

    let request = single_rewrap_request(&key_ctx, Some(temp_dir.path()), false);
    let result = rewrap_file_content(&FileEncContent::new_unchecked(json), &request);

    assert!(
        result.is_err(),
        "rewrap_file_document must fail on invalid signature"
    );
}
