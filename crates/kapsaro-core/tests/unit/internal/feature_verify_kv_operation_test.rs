// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use crate::feature::context::crypto::SigningContext;
use crate::feature::kv::encrypt::encrypt_kv_document;
use crate::format::codec::base64_public::encode_base64url_nopad;
use crate::format::content::KvEncContent;
use crate::format::schema::document::parse_kv_signature_token;
use crate::format::token::TokenCodec;
use crate::io::keystore::storage::load_public_key;
use crate::test_utils::keygen_helpers::build_verified_recipient_keys;
use crate::test_utils::{
    setup_member_key_context, setup_test_keystore_from_fixtures,
    update_active_private_key_expires_at, ALICE_MEMBER_HANDLE,
};

fn build_kv_enc_content() -> String {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    let keystore_root = temp_dir.path().join("keys");
    let kid = key_ctx.kid().to_string();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &kid).unwrap();
    let recipients = build_verified_recipient_keys(std::slice::from_ref(&public_key));

    encrypt_kv_document(
        &HashMap::from([("API_KEY".to_string(), "secret".to_string())]),
        &recipients,
        &SigningContext {
            signing_key: key_ctx.signing_key(),
            signer_kid: &kid,
            signer_pub: public_key,
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap()
}

fn replace_kv_signature_with_zero_tag(content: &str) -> String {
    let lines = content
        .lines()
        .map(|line| {
            if let Some(token) = line.strip_prefix(":SIG ") {
                let mut signature = parse_kv_signature_token(token).unwrap();
                signature.sig = encode_base64url_nopad(&[0u8; 64]);
                let token = TokenCodec::encode(TokenCodec::JsonJcs, &signature).unwrap();
                format!(":SIG {token}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>();
    lines.join("\n") + "\n"
}

#[test]
fn operational_kv_verify_rejects_tampered_signature() {
    let content = replace_kv_signature_with_zero_tag(&build_kv_enc_content());
    let content = KvEncContent::new_unchecked(content);

    let error = super::verify_kv_content_for_operation(&content, false, false).unwrap_err();

    assert!(
        error.to_string().contains("Signature verification failed"),
        "unexpected error: {error}"
    );
}

#[test]
fn operational_kv_verify_preserves_expired_signer_recovery_warning() {
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
    let encrypted = encrypt_kv_document(
        &HashMap::from([("API_KEY".to_string(), "secret".to_string())]),
        &recipients,
        &SigningContext {
            signing_key: key_ctx.signing_key(),
            signer_kid: &kid,
            signer_pub: public_key,
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap();
    let content = KvEncContent::new_unchecked(encrypted);

    let verified = super::verify_kv_content_for_operation(&content, false, true).unwrap();

    assert!(verified.proof().warnings.iter().any(|warning| {
        warning.contains("Artifact signing key has expired.")
            && warning.contains("Reason: expired key use was explicitly allowed.")
    }));
}
