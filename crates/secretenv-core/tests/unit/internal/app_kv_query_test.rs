// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use crate::app::trust::GetPolicy;
use crate::app_test_utils::{build_test_signing_command_options, resolve_test_ssh_context};
use crate::feature::envelope::signature::SigningContext;
use crate::feature::kv::encrypt::encrypt_kv_document;
use crate::format::kv::{DEFAULT_KV_ENC_BASENAME, KV_ENC_EXTENSION};
use crate::format::token::TokenCodec;
use crate::io::keystore::storage::load_public_key;
use crate::test_utils::keygen_helpers::build_verified_recipient_keys;
use crate::test_utils::{
    save_active_public_key_to_workspace, setup_member_key_context,
    setup_test_workspace_from_fixtures, setup_trust_store_for_workspace,
    update_active_private_key_expires_at, with_temp_cwd, ALICE_MEMBER_HANDLE,
};

#[test]
fn kv_read_command_surfaces_expired_artifact_signer_recovery_warning() {
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    update_active_private_key_expires_at(
        temp_dir.path(),
        ALICE_MEMBER_HANDLE,
        "2020-01-01T00:00:00Z",
    );
    let expired_key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    let expired_kid = expired_key_ctx.kid.to_string();
    let keystore_root = temp_dir.path().join("keys");
    let expired_public_key =
        load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &expired_kid).unwrap();

    update_active_private_key_expires_at(
        temp_dir.path(),
        ALICE_MEMBER_HANDLE,
        "2028-01-01T00:00:00Z",
    );
    save_active_public_key_to_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_HANDLE)
        .unwrap();
    let current_key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    let current_kid = current_key_ctx.kid.to_string();
    let current_public_key =
        load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &current_kid).unwrap();
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &current_key_ctx,
    );

    let recipients = build_verified_recipient_keys(std::slice::from_ref(&current_public_key));
    let encrypted = encrypt_kv_document(
        &HashMap::from([("API_KEY".to_string(), "secret".to_string())]),
        &recipients,
        &SigningContext {
            signing_key: &expired_key_ctx.signing_key,
            signer_kid: &expired_kid,
            signer_pub: expired_public_key,
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap();
    std::fs::write(
        workspace_dir
            .join("secrets")
            .join(format!("{DEFAULT_KV_ENC_BASENAME}{KV_ENC_EXTENSION}")),
        encrypted,
    )
    .unwrap();
    let mut options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    options.allow_expired_key = true;

    with_temp_cwd(temp_dir.path(), || {
        let ssh_ctx = Some(resolve_test_ssh_context(&options, ALICE_MEMBER_HANDLE));
        let command = super::resolve_kv_read_command::<GetPolicy>(
            &options,
            Some(ALICE_MEMBER_HANDLE.to_string()),
            None,
            ssh_ctx,
        )
        .unwrap();

        assert!(command.warnings.iter().any(|warning| {
            warning.contains("Artifact signing key has expired")
                && warning.contains("continuing because expired key use was explicitly allowed")
        }));
    });
}

#[test]
fn kv_read_command_ignores_expired_unused_active_key_when_fallback_key_is_valid() {
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let valid_key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    let valid_kid = valid_key_ctx.kid.to_string();
    let keystore_root = temp_dir.path().join("keys");
    let valid_public_key =
        load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &valid_kid).unwrap();
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &valid_key_ctx,
    );

    let recipients = build_verified_recipient_keys(std::slice::from_ref(&valid_public_key));
    let encrypted = encrypt_kv_document(
        &HashMap::from([("API_KEY".to_string(), "secret".to_string())]),
        &recipients,
        &SigningContext {
            signing_key: &valid_key_ctx.signing_key,
            signer_kid: &valid_kid,
            signer_pub: valid_public_key,
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap();
    std::fs::write(
        workspace_dir
            .join("secrets")
            .join(format!("{DEFAULT_KV_ENC_BASENAME}{KV_ENC_EXTENSION}")),
        encrypted,
    )
    .unwrap();

    update_active_private_key_expires_at(
        temp_dir.path(),
        ALICE_MEMBER_HANDLE,
        "2020-01-01T00:00:00Z",
    );
    let expired_active_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    assert_ne!(expired_active_ctx.kid.to_string(), valid_kid);

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);

    with_temp_cwd(temp_dir.path(), || {
        let ssh_ctx = Some(resolve_test_ssh_context(&options, ALICE_MEMBER_HANDLE));
        let command = super::resolve_kv_read_command::<GetPolicy>(
            &options,
            Some(ALICE_MEMBER_HANDLE.to_string()),
            None,
            ssh_ctx,
        )
        .unwrap();

        assert_eq!(
            command.execution.key_ctx.kid.to_string(),
            expired_active_ctx.kid.to_string()
        );
    });
}
