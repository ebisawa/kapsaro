// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::feature::context::crypto::SigningContext;
use crate::feature::encrypt::file::encrypt_file_document;
use crate::feature::verify::file::verify_file_document_report;
use crate::format::codec::base64_public::encode_base64url_nopad;
use crate::format::content::FileEncContent;
use crate::io::keystore::storage::load_public_key;
use crate::test_utils::keygen_helpers::build_verified_recipient_keys;
use crate::test_utils::{
    setup_member_key_context, setup_test_keystore_from_fixtures,
    update_active_private_key_expires_at, ALICE_MEMBER_HANDLE,
};

fn build_file_enc_document() -> crate::model::file_enc::FileEncDocument {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    let keystore_root = temp_dir.path().join("keys");
    let kid = key_ctx.kid().to_string();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &kid).unwrap();
    let recipients = build_verified_recipient_keys(std::slice::from_ref(&public_key));

    encrypt_file_document(
        b"secret",
        &[ALICE_MEMBER_HANDLE.to_string()],
        &recipients,
        &SigningContext {
            signing_key: key_ctx.signing_key(),
            signer_kid: &kid,
            signer_pub: public_key,
            debug: false,
        },
    )
    .unwrap()
}

fn replace_file_signature_with_zero_tag(
    mut doc: crate::model::file_enc::FileEncDocument,
) -> crate::model::file_enc::FileEncDocument {
    doc.signature.sig = encode_base64url_nopad(&[0u8; 64]);
    doc
}

#[test]
fn operational_file_verify_rejects_tampered_signature() {
    let doc = replace_file_signature_with_zero_tag(build_file_enc_document());
    let content = FileEncContent::new_unchecked(serde_json::to_string(&doc).unwrap());

    let error = super::verify_file_content_for_operation(&content, false, false).unwrap_err();

    assert!(
        error.to_string().contains("Signature verification failed"),
        "unexpected error: {error}"
    );
}

#[test]
fn file_verify_report_marks_tampered_signature_failed() {
    let doc = replace_file_signature_with_zero_tag(build_file_enc_document());

    let report = verify_file_document_report(&doc, false);

    assert!(!report.verified);
    assert!(
        report.message.contains("Signature verification failed"),
        "unexpected report: {report:?}"
    );
}

#[test]
fn operational_file_verify_preserves_expired_signer_recovery_warning() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    update_active_private_key_expires_at(
        temp_dir.path(),
        ALICE_MEMBER_HANDLE,
        "2020-01-01T00:00:00Z",
    );
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    let keystore_root = temp_dir.path().join("keys");
    let kid = key_ctx.kid().to_string();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &kid).unwrap();
    let recipients = build_verified_recipient_keys(std::slice::from_ref(&public_key));
    let doc = encrypt_file_document(
        b"secret",
        &[ALICE_MEMBER_HANDLE.to_string()],
        &recipients,
        &SigningContext {
            signing_key: key_ctx.signing_key(),
            signer_kid: &kid,
            signer_pub: public_key,
            debug: false,
        },
    )
    .unwrap();
    let content = FileEncContent::new_unchecked(serde_json::to_string(&doc).unwrap());

    let verified = super::verify_file_content_for_operation(&content, false, true).unwrap();

    assert!(verified.proof().warnings.iter().any(|warning| {
        warning.contains("Artifact signing key has expired.")
            && warning.contains("Reason: expired key use was explicitly allowed.")
    }));
}
