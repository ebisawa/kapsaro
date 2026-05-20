// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::feature::encrypt::file::encrypt_file_document;
use crate::feature::envelope::signature::SigningContext;
use crate::format::content::FileEncContent;
use crate::io::keystore::storage::load_public_key;
use crate::test_utils::keygen_helpers::build_verified_recipient_keys;
use crate::test_utils::{
    setup_member_key_context, setup_test_keystore_from_fixtures,
    update_active_private_key_expires_at, ALICE_MEMBER_HANDLE,
};

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
    let kid = key_ctx.kid.to_string();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &kid).unwrap();
    let recipients = build_verified_recipient_keys(std::slice::from_ref(&public_key));
    let doc = encrypt_file_document(
        b"secret",
        &[ALICE_MEMBER_HANDLE.to_string()],
        &recipients,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: &kid,
            signer_pub: public_key,
            debug: false,
        },
    )
    .unwrap();
    let content = FileEncContent::new_unchecked(serde_json::to_string(&doc).unwrap());

    let verified = super::verify_file_content_for_operation(&content, false, true).unwrap();

    assert!(verified.proof.warnings.iter().any(|warning| {
        warning.contains("Artifact signing key has expired")
            && warning.contains("continuing because expired key use was explicitly allowed")
    }));
}
