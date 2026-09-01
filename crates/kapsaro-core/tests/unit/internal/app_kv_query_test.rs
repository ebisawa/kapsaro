// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::Path;

use crate::app::trust::{GetPolicy, ListPolicy};
use crate::app_test_utils::build_test_signing_command_options;
use crate::cli_api::test_support::storage::keystore::active::set_active_kid;
use crate::cli_api::test_support::storage::keystore::storage::load_public_key;
use crate::crypto::types::keys::MacKey;
use crate::feature::context::crypto::SigningContext;
use crate::feature::envelope::signature::sign_kv_document;
use crate::feature::kv::encrypt::encrypt_kv_map_with_wrap_mutation;
use crate::format::kv::{DEFAULT_KV_ENC_BASENAME, KV_ENC_EXTENSION};
use crate::format::token::TokenCodec;
use crate::test_utils::keygen_helpers::build_verified_recipient_keys;
use crate::test_utils::{
    save_active_public_key_to_workspace, setup_member_key_context,
    setup_test_workspace_from_fixtures, setup_trust_store_for_workspace,
    update_active_private_key_expires_at, with_temp_cwd, EnvGuard, ALICE_MEMBER_HANDLE,
    BOB_MEMBER_HANDLE,
};
use zeroize::Zeroizing;

struct InteractiveOverrideGuard;

impl InteractiveOverrideGuard {
    fn set(value: bool) -> Self {
        crate::support::tty::set_interactive_override(Some(value));
        Self
    }
}

impl Drop for InteractiveOverrideGuard {
    fn drop(&mut self) {
        crate::support::tty::set_interactive_override(None);
    }
}

#[test]
fn test_kv_read_unknown_active_recipient_non_interactive_error() {
    let _env = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::set_var("KAPSARO_STRICT_KEY_CHECKING", "yes");
    let _interactive = InteractiveOverrideGuard::set(false);
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let alice_ctx = setup_member_key_context(&home, ALICE_MEMBER_HANDLE, None);
    let bob_ctx = setup_member_key_context(&home, BOB_MEMBER_HANDLE, None);
    let keystore_root = home.path().join("keys");
    let alice = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, alice_ctx.kid()).unwrap();
    let bob = load_public_key(&keystore_root, BOB_MEMBER_HANDLE, bob_ctx.kid()).unwrap();
    let recipients = build_verified_recipient_keys(&[alice.clone(), bob]);
    let encrypted = encrypt_kv_map_with_wrap_mutation(
        &HashMap::from([("API_KEY".to_string(), "secret".to_string())]),
        &recipients,
        &SigningContext {
            signing_key: alice_ctx.signing_key(),
            signer_kid: alice_ctx.kid(),
            signer_pub: alice,
        },
        TokenCodec::JsonJcs,
        false,
        |_| Ok(()),
    )
    .unwrap();
    std::fs::write(
        workspace
            .join("secrets")
            .join(format!("{DEFAULT_KV_ENC_BASENAME}{KV_ENC_EXTENSION}")),
        encrypted,
    )
    .unwrap();
    let options = build_test_signing_command_options(home.path(), &workspace);

    let error = resolve_kv_read_command_for_test::<GetPolicy>(
        &options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        None,
    )
    .err()
    .expect("non-interactive unknown recipient must fail");

    assert_eq!(error.kind(), crate::ErrorKind::Verify);
    assert_eq!(error.rule(), Some("E_TRUST_RECIPIENT_UNKNOWN"));
    assert!(error.to_string().contains(BOB_MEMBER_HANDLE));
    assert!(error.to_string().contains(bob_ctx.kid()));
}

#[test]
fn test_kv_read_unknown_active_recipient_skips_review_when_strict_checking_is_disabled() {
    let _env = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::set_var("KAPSARO_STRICT_KEY_CHECKING", "no");
    let _interactive = InteractiveOverrideGuard::set(false);
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let alice_ctx = setup_member_key_context(&home, ALICE_MEMBER_HANDLE, None);
    let bob_ctx = setup_member_key_context(&home, BOB_MEMBER_HANDLE, None);
    let keystore_root = home.path().join("keys");
    let alice = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, alice_ctx.kid()).unwrap();
    let bob = load_public_key(&keystore_root, BOB_MEMBER_HANDLE, bob_ctx.kid()).unwrap();
    let recipients = build_verified_recipient_keys(&[alice.clone(), bob]);
    let encrypted = encrypt_kv_map_with_wrap_mutation(
        &HashMap::from([("API_KEY".to_string(), "secret".to_string())]),
        &recipients,
        &SigningContext {
            signing_key: alice_ctx.signing_key(),
            signer_kid: alice_ctx.kid(),
            signer_pub: alice,
        },
        TokenCodec::JsonJcs,
        false,
        |_| Ok(()),
    )
    .unwrap();
    std::fs::write(
        workspace
            .join("secrets")
            .join(format!("{DEFAULT_KV_ENC_BASENAME}{KV_ENC_EXTENSION}")),
        encrypted,
    )
    .unwrap();
    let options = build_test_signing_command_options(home.path(), &workspace);

    let command = resolve_kv_read_command_for_test::<GetPolicy>(
        &options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        None,
    )
    .unwrap();

    assert!(matches!(
        command.recipient_outcome,
        crate::app::trust::RecipientTrustOutcome::Accepted
    ));
}

#[test]
fn test_kv_read_command_warns_about_unresolved_historical_recipient() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::set_var("KAPSARO_STRICT_KEY_CHECKING", "no");
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let key_ctx = setup_member_key_context(&home, ALICE_MEMBER_HANDLE, None);
    let keystore_root = home.path().join("keys");
    let alice = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, key_ctx.kid()).unwrap();
    let bob_kid = crate::cli_api::test_support::storage::keystore::storage::list_kids(
        &keystore_root,
        BOB_MEMBER_HANDLE,
    )
    .unwrap()
    .remove(0);
    let bob = load_public_key(&keystore_root, BOB_MEMBER_HANDLE, &bob_kid).unwrap();
    let recipients = build_verified_recipient_keys(&[alice.clone(), bob]);
    let encrypted = encrypt_kv_map_with_wrap_mutation(
        &HashMap::from([("API_KEY".to_string(), "secret".to_string())]),
        &recipients,
        &SigningContext {
            signing_key: key_ctx.signing_key(),
            signer_kid: key_ctx.kid(),
            signer_pub: alice,
        },
        TokenCodec::JsonJcs,
        false,
        |_| Ok(()),
    )
    .unwrap();
    std::fs::write(
        workspace
            .join("secrets")
            .join(format!("{DEFAULT_KV_ENC_BASENAME}{KV_ENC_EXTENSION}")),
        encrypted,
    )
    .unwrap();
    crate::io::workspace::members::test_support::remove_active_member(
        &workspace,
        BOB_MEMBER_HANDLE,
    )
    .unwrap();
    let options = build_test_signing_command_options(home.path(), &workspace);

    let command = resolve_kv_read_command_for_test::<GetPolicy>(
        &options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        None,
    )
    .unwrap();

    assert!(command.warnings.iter().any(|warning| {
        warning.contains("Recipient kid is not active.")
            && warning.contains(&bob_kid)
            && warning.contains("historical metadata")
            && warning.contains("kapsaro rewrap")
    }));
}

#[cfg(unix)]
#[test]
fn test_kv_read_input_uses_the_workspace_fixed_by_the_execution() {
    use std::fs;

    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let (_replacement_home, replacement_workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let key_ctx = setup_member_key_context(&home, ALICE_MEMBER_HANDLE, None);
    let file_name = format!("{DEFAULT_KV_ENC_BASENAME}{KV_ENC_EXTENSION}");
    let kid = key_ctx.kid().to_string();
    let public_key = load_public_key(&home.path().join("keys"), ALICE_MEMBER_HANDLE, &kid).unwrap();
    let recipients = build_verified_recipient_keys(std::slice::from_ref(&public_key));
    let encrypt = |value: &str| {
        encrypt_kv_map_with_wrap_mutation(
            &HashMap::from([("SOURCE".to_string(), value.to_string())]),
            &recipients,
            &SigningContext {
                signing_key: key_ctx.signing_key(),
                signer_kid: &kid,
                signer_pub: public_key.clone(),
            },
            TokenCodec::JsonJcs,
            false,
            |_| Ok(()),
        )
        .unwrap()
    };
    let artifact_a = encrypt("from-a");
    let artifact_b = encrypt("from-b");
    fs::write(workspace.join("secrets").join(&file_name), &artifact_a).unwrap();
    fs::write(
        replacement_workspace.join("secrets").join(&file_name),
        artifact_b,
    )
    .unwrap();
    let options = build_test_signing_command_options(home.path(), &workspace);
    let execution = crate::app::context::execution::resolve_read_execution(
        &options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        None,
    )
    .unwrap();
    let opened_workspace = workspace.with_extension("opened");
    fs::rename(&workspace, &opened_workspace).unwrap();
    fs::rename(&replacement_workspace, &workspace).unwrap();

    let input = super::load_kv_read_input(&execution, None).unwrap();

    assert_eq!(input.artifact.as_str(), artifact_a);
    assert_eq!(input.file_name, file_name);
    assert!(input
        .file_path
        .ends_with(Path::new("secrets").join(file_name)));
}

#[test]
fn kv_read_command_surfaces_expired_artifact_signer_recovery_warning() {
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    update_active_private_key_expires_at(
        temp_dir.path(),
        ALICE_MEMBER_HANDLE,
        "2020-01-01T00:00:00Z",
    );
    let expired_key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    let expired_kid = expired_key_ctx.kid().to_string();
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
    let current_kid = current_key_ctx.kid().to_string();
    let current_public_key =
        load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &current_kid).unwrap();
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &current_key_ctx,
    );

    let recipients = build_verified_recipient_keys(std::slice::from_ref(&current_public_key));
    let encrypted = encrypt_kv_map_with_wrap_mutation(
        &HashMap::from([("API_KEY".to_string(), "secret".to_string())]),
        &recipients,
        &SigningContext {
            signing_key: expired_key_ctx.signing_key(),
            signer_kid: &expired_kid,
            signer_pub: expired_public_key,
        },
        TokenCodec::JsonJcs,
        false,
        |_| Ok(()),
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
        let command = resolve_kv_read_command_for_test::<GetPolicy>(
            &options,
            Some(ALICE_MEMBER_HANDLE.to_string()),
            None,
        )
        .unwrap();

        assert!(command.warnings.iter().any(|warning| {
            warning.contains("Artifact signing key has expired.")
                && warning.contains("Reason: expired key use was explicitly allowed.")
        }));
    });
}

#[test]
fn kv_read_command_ignores_expired_unused_active_key_when_fallback_key_is_valid() {
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let valid_key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    let valid_kid = valid_key_ctx.kid().to_string();
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
    let encrypted = encrypt_kv_map_with_wrap_mutation(
        &HashMap::from([("API_KEY".to_string(), "secret".to_string())]),
        &recipients,
        &SigningContext {
            signing_key: valid_key_ctx.signing_key(),
            signer_kid: &valid_kid,
            signer_pub: valid_public_key,
        },
        TokenCodec::JsonJcs,
        false,
        |_| Ok(()),
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
    assert_ne!(expired_active_ctx.kid().to_string(), valid_kid);

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);

    with_temp_cwd(temp_dir.path(), || {
        let command = resolve_kv_read_command_for_test::<GetPolicy>(
            &options,
            Some(ALICE_MEMBER_HANDLE.to_string()),
            None,
        )
        .unwrap();

        assert_eq!(
            command.execution.key_ctx.kid().to_string(),
            expired_active_ctx.kid().to_string()
        );
    });
}

#[test]
fn kv_list_command_rejects_invalid_key_possession_without_decrypting_entries() {
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    let keystore_root = temp_dir.path().join("keys");
    let kid = key_ctx.kid().to_string();
    set_active_kid(ALICE_MEMBER_HANDLE, &kid, &keystore_root).unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &kid).unwrap();
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    let recipients = build_verified_recipient_keys(std::slice::from_ref(&public_key));
    let encrypted = encrypt_kv_map_with_wrap_mutation(
        &HashMap::from([("API_KEY".to_string(), "secret".to_string())]),
        &recipients,
        &SigningContext {
            signing_key: key_ctx.signing_key(),
            signer_kid: &kid,
            signer_pub: public_key,
        },
        TokenCodec::JsonJcs,
        false,
        |_| Ok(()),
    )
    .unwrap();
    let unsigned = strip_kv_signature(&encrypted);
    let signed_with_wrong_mac = sign_kv_document(
        &unsigned,
        &MacKey::from_zeroizing(Zeroizing::new([9u8; 32])),
        &SigningContext {
            signing_key: key_ctx.signing_key(),
            signer_kid: &kid,
            signer_pub: load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &kid).unwrap(),
        },
        TokenCodec::JsonJcs,
    )
    .unwrap();
    std::fs::write(
        workspace_dir
            .join("secrets")
            .join(format!("{DEFAULT_KV_ENC_BASENAME}{KV_ENC_EXTENSION}")),
        signed_with_wrong_mac,
    )
    .unwrap();
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);

    with_temp_cwd(temp_dir.path(), || {
        let command = resolve_kv_read_command_for_test::<ListPolicy>(
            &options,
            Some(ALICE_MEMBER_HANDLE.to_string()),
            None,
        )
        .unwrap();

        let error = crate::api::kv::TrustedKvEncArtifact::from_authorized(
            &command.verified,
            &command.execution.key_ctx,
            crate::api::kv::KvReadOperation::List,
            options.operation_options(),
        )
        .err()
        .expect("invalid key-possession MAC must fail authorization");
        assert!(error.to_string().contains("E_KEY_POSSESSION_MAC_INVALID"));
    });
}

fn resolve_kv_read_command_for_test<P>(
    options: &crate::app::context::options::CommonCommandOptions,
    member_handle: Option<String>,
    file_name: Option<&str>,
) -> crate::Result<TestKvReadContext>
where
    P: crate::app::trust::ReadTrustPolicy,
{
    let execution =
        crate::app::context::execution::resolve_read_execution(options, member_handle, None)?;
    let input = super::load_kv_read_input(&execution, file_name)?;
    let verified = input.artifact.verify(options.operation_options())?;
    let trust = super::evaluate_kv_read_trust_plan::<P>(options, &execution, &verified)?;
    Ok(TestKvReadContext {
        execution,
        verified,
        recipient_outcome: trust.recipient_outcome,
        warnings: trust.warnings,
    })
}

struct TestKvReadContext {
    execution: crate::app::context::execution::ExecutionContext,
    verified: crate::api::kv::VerifiedKvEncArtifact,
    recipient_outcome: crate::app::trust::RecipientTrustOutcome,
    warnings: Vec<String>,
}

fn strip_kv_signature(content: &str) -> String {
    content
        .lines()
        .take_while(|line| !line.starts_with(":SIG "))
        .map(|line| format!("{line}\n"))
        .collect()
}
