// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app_test_utils::build_test_signing_command_options;
use crate::cli_api::test_support::storage::keystore::storage::load_public_key;
use crate::feature::context::crypto::SigningContext;
use crate::feature::encrypt::file::encrypt_file_document;
use crate::feature::envelope::key_schedule::FileKeySchedule;
use crate::feature::envelope::signature::sign_file_document;
use crate::feature::envelope::unwrap::unwrap_master_key_for_file_with_context;
use crate::feature::verify::file::verify_file_document;
use crate::test_utils::keygen_helpers::build_verified_recipient_keys;
use crate::test_utils::{
    build_expiring_soon_timestamp, save_active_public_key_to_workspace, setup_member_key_context,
    setup_test_workspace_from_fixtures, setup_trust_store_for_workspace,
    update_active_private_key_expires_at, with_temp_cwd, EnvGuard, ALICE_MEMBER_HANDLE,
    BOB_MEMBER_HANDLE, CAROL_MEMBER_HANDLE,
};

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
fn test_decrypt_unknown_active_signer_non_interactive_error() {
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
    let recipients = build_verified_recipient_keys(std::slice::from_ref(&alice));
    let document = encrypt_file_document(
        b"secret",
        &[ALICE_MEMBER_HANDLE.to_string()],
        &recipients,
        &SigningContext {
            signing_key: bob_ctx.signing_key(),
            signer_kid: bob_ctx.kid(),
            signer_pub: bob,
        },
    )
    .unwrap();
    let options = build_test_signing_command_options(home.path(), &workspace);

    let error = resolve_decrypt_file_command_for_test(
        &options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        None,
        serde_json::to_string(&document).unwrap(),
        "unknown-signer.fileenc",
    )
    .err()
    .expect("non-interactive unknown signer must fail");

    assert_eq!(error.kind(), crate::ErrorKind::Verify);
    assert_eq!(error.rule(), Some("E_TRUST_UNKNOWN_SIGNER"));
    assert!(error.to_string().contains(BOB_MEMBER_HANDLE));
    assert!(error.to_string().contains(bob_ctx.kid()));
}

#[test]
fn test_decrypt_unknown_signer_precedes_recipient_handle_mismatch_non_interactive_error() {
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
    let recipients = build_verified_recipient_keys(&[alice.clone(), bob.clone()]);
    let mut document = encrypt_file_document(
        b"secret",
        &[
            ALICE_MEMBER_HANDLE.to_string(),
            BOB_MEMBER_HANDLE.to_string(),
        ],
        &recipients,
        &SigningContext {
            signing_key: bob_ctx.signing_key(),
            signer_kid: bob_ctx.kid(),
            signer_pub: bob.clone(),
        },
    )
    .unwrap();
    let verified = verify_file_document(&document).unwrap();
    let master_key =
        unwrap_master_key_for_file_with_context(&verified, ALICE_MEMBER_HANDLE, &alice_ctx)
            .unwrap()
            .value;
    document
        .protected
        .wrap
        .iter_mut()
        .find(|wrap| wrap.kid == bob_ctx.kid())
        .unwrap()
        .recipient_handle = CAROL_MEMBER_HANDLE.to_string();
    let mac_key = FileKeySchedule::extract(&master_key, &document.protected.sid)
        .unwrap()
        .derive_mac_key()
        .unwrap();
    document.signature = sign_file_document(
        &document.protected,
        &mac_key,
        bob_ctx.signing_key(),
        bob_ctx.kid(),
        bob,
    )
    .unwrap();
    let options = build_test_signing_command_options(home.path(), &workspace);

    let error = resolve_decrypt_file_command_for_test(
        &options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        None,
        serde_json::to_string(&document).unwrap(),
        "signer-priority.fileenc",
    )
    .err()
    .expect("unknown signer must precede recipient handle validation");

    assert_eq!(error.kind(), crate::ErrorKind::Verify);
    assert_eq!(error.rule(), Some("E_TRUST_UNKNOWN_SIGNER"));
    assert!(error.to_string().contains(BOB_MEMBER_HANDLE));
    assert!(error.to_string().contains(bob_ctx.kid()));
}

#[test]
fn test_decrypt_unknown_active_recipient_non_interactive_error() {
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
    let document = encrypt_file_document(
        b"secret",
        &[
            ALICE_MEMBER_HANDLE.to_string(),
            BOB_MEMBER_HANDLE.to_string(),
        ],
        &recipients,
        &SigningContext {
            signing_key: alice_ctx.signing_key(),
            signer_kid: alice_ctx.kid(),
            signer_pub: alice,
        },
    )
    .unwrap();
    let options = build_test_signing_command_options(home.path(), &workspace);

    let error = resolve_decrypt_file_command_for_test(
        &options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        None,
        serde_json::to_string(&document).unwrap(),
        "unknown-recipient.fileenc",
    )
    .err()
    .expect("non-interactive unknown recipient must fail");

    assert_eq!(error.kind(), crate::ErrorKind::Verify);
    assert_eq!(error.rule(), Some("E_TRUST_RECIPIENT_UNKNOWN"));
    assert!(error.to_string().contains(BOB_MEMBER_HANDLE));
    assert!(error.to_string().contains(bob_ctx.kid()));
}

#[test]
fn test_decrypt_non_member_acceptance_non_interactive_error() {
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
    let recipients = build_verified_recipient_keys(std::slice::from_ref(&alice));
    let document = encrypt_file_document(
        b"secret",
        &[ALICE_MEMBER_HANDLE.to_string()],
        &recipients,
        &SigningContext {
            signing_key: bob_ctx.signing_key(),
            signer_kid: bob_ctx.kid(),
            signer_pub: bob,
        },
    )
    .unwrap();
    crate::io::workspace::members::test_support::remove_active_member(
        &workspace,
        BOB_MEMBER_HANDLE,
    )
    .unwrap();
    let mut options = build_test_signing_command_options(home.path(), &workspace);
    options.allow_non_member = true;

    let error = resolve_decrypt_file_command_for_test(
        &options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        None,
        serde_json::to_string(&document).unwrap(),
        "non-member.fileenc",
    )
    .err()
    .expect("non-interactive non-member acceptance must fail");

    assert_eq!(error.kind(), crate::ErrorKind::Verify);
    assert_eq!(error.rule(), Some("E_TRUST_NON_MEMBER"));
    assert!(error.to_string().contains(BOB_MEMBER_HANDLE));
    assert!(error.to_string().contains(bob_ctx.kid()));
}

#[test]
fn test_decrypt_unknown_active_signer_interactive_review() {
    let _env = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::set_var("KAPSARO_STRICT_KEY_CHECKING", "yes");
    let _interactive = InteractiveOverrideGuard::set(true);
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let alice_ctx = setup_member_key_context(&home, ALICE_MEMBER_HANDLE, None);
    let bob_ctx = setup_member_key_context(&home, BOB_MEMBER_HANDLE, None);
    let keystore_root = home.path().join("keys");
    let alice = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, alice_ctx.kid()).unwrap();
    let bob = load_public_key(&keystore_root, BOB_MEMBER_HANDLE, bob_ctx.kid()).unwrap();
    let recipients = build_verified_recipient_keys(&[alice.clone(), bob.clone()]);
    let document = encrypt_file_document(
        b"secret",
        &[
            ALICE_MEMBER_HANDLE.to_string(),
            BOB_MEMBER_HANDLE.to_string(),
        ],
        &recipients,
        &SigningContext {
            signing_key: bob_ctx.signing_key(),
            signer_kid: bob_ctx.kid(),
            signer_pub: bob,
        },
    )
    .unwrap();
    let options = build_test_signing_command_options(home.path(), &workspace);

    let command = resolve_decrypt_file_command_for_test(
        &options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        None,
        serde_json::to_string(&document).unwrap(),
        "interactive-review.fileenc",
    )
    .unwrap();

    let crate::app::trust::SignerTrustOutcome::NeedsKnownKeyApproval(signer) =
        command.signer_outcome
    else {
        panic!("interactive unknown signer must require known-key approval");
    };
    assert_eq!(signer.member_handle().as_str(), BOB_MEMBER_HANDLE);
    assert_eq!(signer.kid().as_str(), bob_ctx.kid());
    assert!(matches!(
        command.recipient_outcome,
        crate::app::trust::RecipientTrustOutcome::Accepted
    ));
}

#[test]
fn test_decrypt_unknown_active_signer_skips_review_when_strict_checking_is_disabled() {
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
    let recipients = build_verified_recipient_keys(std::slice::from_ref(&alice));
    let document = encrypt_file_document(
        b"secret",
        &[ALICE_MEMBER_HANDLE.to_string()],
        &recipients,
        &SigningContext {
            signing_key: bob_ctx.signing_key(),
            signer_kid: bob_ctx.kid(),
            signer_pub: bob,
        },
    )
    .unwrap();
    let options = build_test_signing_command_options(home.path(), &workspace);

    let command = resolve_decrypt_file_command_for_test(
        &options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        None,
        serde_json::to_string(&document).unwrap(),
        "strict-disabled-signer.fileenc",
    )
    .unwrap();

    assert!(matches!(
        command.signer_outcome,
        crate::app::trust::SignerTrustOutcome::Accepted
    ));
}

#[test]
fn test_decrypt_unknown_active_recipient_interactive_review() {
    let _env = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::set_var("KAPSARO_STRICT_KEY_CHECKING", "yes");
    let _interactive = InteractiveOverrideGuard::set(true);
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let alice_ctx = setup_member_key_context(&home, ALICE_MEMBER_HANDLE, None);
    let bob_ctx = setup_member_key_context(&home, BOB_MEMBER_HANDLE, None);
    let keystore_root = home.path().join("keys");
    let alice = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, alice_ctx.kid()).unwrap();
    let bob = load_public_key(&keystore_root, BOB_MEMBER_HANDLE, bob_ctx.kid()).unwrap();
    let recipients = build_verified_recipient_keys(&[alice.clone(), bob]);
    let document = encrypt_file_document(
        b"secret",
        &[
            ALICE_MEMBER_HANDLE.to_string(),
            BOB_MEMBER_HANDLE.to_string(),
        ],
        &recipients,
        &SigningContext {
            signing_key: alice_ctx.signing_key(),
            signer_kid: alice_ctx.kid(),
            signer_pub: alice,
        },
    )
    .unwrap();
    let options = build_test_signing_command_options(home.path(), &workspace);

    let command = resolve_decrypt_file_command_for_test(
        &options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        None,
        serde_json::to_string(&document).unwrap(),
        "interactive-recipient-review.fileenc",
    )
    .unwrap();

    assert!(matches!(
        command.signer_outcome,
        crate::app::trust::SignerTrustOutcome::Accepted
    ));
    let crate::app::trust::RecipientTrustOutcome::NeedsManualApproval(recipients) =
        command.recipient_outcome
    else {
        panic!("interactive unknown recipient must require manual approval");
    };
    assert_eq!(recipients.len(), 1);
    assert_eq!(recipients[0].member_handle().as_str(), BOB_MEMBER_HANDLE);
    assert_eq!(recipients[0].kid().as_str(), bob_ctx.kid());
}

#[test]
fn test_decrypt_command_warns_about_unresolved_historical_recipient_when_review_is_skipped() {
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
    let document = encrypt_file_document(
        b"secret",
        &[
            ALICE_MEMBER_HANDLE.to_string(),
            BOB_MEMBER_HANDLE.to_string(),
        ],
        &recipients,
        &SigningContext {
            signing_key: key_ctx.signing_key(),
            signer_kid: key_ctx.kid(),
            signer_pub: alice,
        },
    )
    .unwrap();
    crate::io::workspace::members::test_support::remove_active_member(
        &workspace,
        BOB_MEMBER_HANDLE,
    )
    .unwrap();
    let options = build_test_signing_command_options(home.path(), &workspace);

    let command = resolve_decrypt_file_command_for_test(
        &options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        None,
        serde_json::to_string(&document).unwrap(),
        "historical.fileenc",
    )
    .unwrap();

    assert!(command.warnings.iter().any(|warning| {
        warning.contains("Recipient kid is not active.")
            && warning.contains(&bob_kid)
            && warning.contains("historical metadata")
            && warning.contains("kapsaro rewrap")
    }));
}

#[test]
fn decrypt_command_surfaces_expired_artifact_signer_recovery_warning() {
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
    let doc = encrypt_file_document(
        b"secret",
        &[ALICE_MEMBER_HANDLE.to_string()],
        &recipients,
        &SigningContext {
            signing_key: expired_key_ctx.signing_key(),
            signer_kid: &expired_kid,
            signer_pub: expired_public_key,
        },
    )
    .unwrap();
    let content = serde_json::to_string(&doc).unwrap();
    let mut options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    options.allow_expired_key = true;

    with_temp_cwd(temp_dir.path(), || {
        let command = resolve_decrypt_file_command_for_test(
            &options,
            Some(ALICE_MEMBER_HANDLE.to_string()),
            None,
            content,
            "test.fileenc",
        )
        .unwrap();

        assert!(command.warnings.iter().any(|warning| {
            warning.contains("Artifact signing key has expired.")
                && warning.contains("Reason: expired key use was explicitly allowed.")
        }));
    });
}

fn resolve_decrypt_file_command_for_test(
    options: &crate::app::context::options::CommonCommandOptions,
    member_handle: Option<String>,
    kid: Option<&str>,
    content: String,
    source_name: &str,
) -> crate::Result<TestDecryptContext> {
    let artifact = crate::api::file::FileEncArtifact::load_reader(content.as_bytes(), source_name)?;
    let verified = artifact.verify(options.operation_options())?;
    let execution =
        crate::app::context::execution::resolve_read_execution(options, member_handle, kid)?;
    let trust = super::evaluate_decrypt_file_trust_plan(options, &execution, &verified)?;
    Ok(TestDecryptContext {
        execution,
        signer_outcome: trust.signer_outcome,
        recipient_outcome: trust.recipient_outcome,
        warnings: trust.warnings,
    })
}

struct TestDecryptContext {
    execution: crate::app::context::execution::ExecutionContext,
    signer_outcome: crate::app::trust::SignerTrustOutcome,
    recipient_outcome: crate::app::trust::RecipientTrustOutcome,
    warnings: Vec<String>,
}

#[test]
fn decrypt_command_coalesces_local_key_pair_expiry_warning() {
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(temp_dir.path(), ALICE_MEMBER_HANDLE, &expires_at);
    save_active_public_key_to_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_HANDLE)
        .unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    let kid = key_ctx.kid().to_string();
    let keystore_root = temp_dir.path().join("keys");
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &kid).unwrap();
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &key_ctx,
    );

    let recipients = build_verified_recipient_keys(std::slice::from_ref(&public_key));
    let doc = encrypt_file_document(
        b"secret",
        &[ALICE_MEMBER_HANDLE.to_string()],
        &recipients,
        &SigningContext {
            signing_key: key_ctx.signing_key(),
            signer_kid: &kid,
            signer_pub: public_key,
        },
    )
    .unwrap();
    let content = serde_json::to_string(&doc).unwrap();
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);

    with_temp_cwd(temp_dir.path(), || {
        let command = resolve_decrypt_file_command_for_test(
            &options,
            Some(ALICE_MEMBER_HANDLE.to_string()),
            None,
            content,
            "test.fileenc",
        )
        .unwrap();

        let expiry_warning_count = command
            .warnings
            .iter()
            .filter(|warning| warning.contains(&expires_at))
            .count();
        assert_eq!(expiry_warning_count, 1, "{:?}", command.warnings);
        assert!(command
            .warnings
            .iter()
            .any(|warning| warning.contains("Local key expires in")));
    });
}

#[test]
fn decrypt_command_preserves_historical_signer_expiry_warning_with_same_expires_at() {
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(temp_dir.path(), ALICE_MEMBER_HANDLE, &expires_at);
    let historical_key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    let historical_kid = historical_key_ctx.kid().to_string();
    let keystore_root = temp_dir.path().join("keys");
    let historical_public_key =
        load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &historical_kid).unwrap();

    update_active_private_key_expires_at(temp_dir.path(), ALICE_MEMBER_HANDLE, &expires_at);
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
    let doc = encrypt_file_document(
        b"secret",
        &[ALICE_MEMBER_HANDLE.to_string()],
        &recipients,
        &SigningContext {
            signing_key: historical_key_ctx.signing_key(),
            signer_kid: &historical_kid,
            signer_pub: historical_public_key,
        },
    )
    .unwrap();
    let content = serde_json::to_string(&doc).unwrap();
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);

    with_temp_cwd(temp_dir.path(), || {
        let command = resolve_decrypt_file_command_for_test(
            &options,
            Some(ALICE_MEMBER_HANDLE.to_string()),
            None,
            content,
            "test.fileenc",
        )
        .unwrap();

        assert!(command
            .warnings
            .iter()
            .any(|warning| warning.contains("Local key expires in")));
        assert!(command
            .warnings
            .iter()
            .any(|warning| warning.contains("Artifact signing key expires in")));
    });
}

#[test]
fn decrypt_command_coalesces_selected_fallback_key_pair_expiry_warning() {
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(temp_dir.path(), ALICE_MEMBER_HANDLE, &expires_at);
    let old_key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    let old_kid = old_key_ctx.kid().to_string();
    let keystore_root = temp_dir.path().join("keys");
    let old_public_key = load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &old_kid).unwrap();

    update_active_private_key_expires_at(
        temp_dir.path(),
        ALICE_MEMBER_HANDLE,
        "2028-01-01T00:00:00Z",
    );
    save_active_public_key_to_workspace(temp_dir.path(), &workspace_dir, ALICE_MEMBER_HANDLE)
        .unwrap();
    let current_key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    setup_trust_store_for_workspace(
        temp_dir.path(),
        &workspace_dir,
        ALICE_MEMBER_HANDLE,
        &current_key_ctx,
    );

    let recipients = build_verified_recipient_keys(std::slice::from_ref(&old_public_key));
    let doc = encrypt_file_document(
        b"secret",
        &[ALICE_MEMBER_HANDLE.to_string()],
        &recipients,
        &SigningContext {
            signing_key: old_key_ctx.signing_key(),
            signer_kid: &old_kid,
            signer_pub: old_public_key,
        },
    )
    .unwrap();
    let content = serde_json::to_string(&doc).unwrap();
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);

    with_temp_cwd(temp_dir.path(), || {
        let command = resolve_decrypt_file_command_for_test(
            &options,
            Some(ALICE_MEMBER_HANDLE.to_string()),
            None,
            content,
            "test.fileenc",
        )
        .unwrap();

        let expiry_warning_count = command
            .warnings
            .iter()
            .filter(|warning| warning.contains(&expires_at))
            .count();
        assert_eq!(expiry_warning_count, 1, "{:?}", command.warnings);
        assert!(command
            .warnings
            .iter()
            .any(|warning| warning.contains("Local key expires in")));
    });
}

#[test]
fn decrypt_command_ignores_expired_unused_active_key_when_fallback_key_is_valid() {
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
    let doc = encrypt_file_document(
        b"secret",
        &[ALICE_MEMBER_HANDLE.to_string()],
        &recipients,
        &SigningContext {
            signing_key: valid_key_ctx.signing_key(),
            signer_kid: &valid_kid,
            signer_pub: valid_public_key,
        },
    )
    .unwrap();
    let content = serde_json::to_string(&doc).unwrap();

    update_active_private_key_expires_at(
        temp_dir.path(),
        ALICE_MEMBER_HANDLE,
        "2020-01-01T00:00:00Z",
    );
    let expired_active_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, None);
    assert_ne!(expired_active_ctx.kid().to_string(), valid_kid);

    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);

    with_temp_cwd(temp_dir.path(), || {
        let command = resolve_decrypt_file_command_for_test(
            &options,
            Some(ALICE_MEMBER_HANDLE.to_string()),
            None,
            content,
            "test.fileenc",
        )
        .unwrap();

        assert_eq!(
            command.execution.key_ctx.kid().to_string(),
            expired_active_ctx.kid().to_string()
        );
    });
}
