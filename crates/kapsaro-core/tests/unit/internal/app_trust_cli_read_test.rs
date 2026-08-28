// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CLI read exception binding tests.
//! Ensures one-shot policy exceptions cannot weaken current membership or target identity.

use crate::api::file::{FileEncArtifact, VerifiedFileEncArtifact};
use crate::api::key::{KeyContext, LocalKeyStore, MemberHandle};
use crate::api::kv::{KvEncArtifact, KvInputEntry, KvReadOperation, VerifiedKvEncArtifact};
use crate::api::operation::OperationOptions;
use crate::api::secret::SecretString;
use crate::api::trust::{CurrentMemberSnapshot, TrustDecision, TrustPolicyEvaluator};
use crate::app::context::execution::resolve_read_trust_evaluator;
use crate::app::trust::{SignerTrustOutcome, TrustApprovalCandidateBuilder};
use crate::app_test_utils::build_test_execution_context;
use crate::cli_api::test_support::storage::keystore::storage::load_public_key;
use crate::io::workspace::members::test_support::remove_active_member as remove_member;
use crate::test_utils::{
    setup_member_key_context, setup_test_workspace_from_fixtures, EnvGuard, ALICE_MEMBER_HANDLE,
    BOB_MEMBER_HANDLE,
};

use super::{evaluate_file_after_cli_review, evaluate_kv_after_cli_review};

fn member_handle(value: &str) -> MemberHandle {
    MemberHandle::try_from(value).expect("valid member handle")
}

#[test]
fn test_strict_no_still_rejects_signer_removed_from_current_members() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::set_var("KAPSARO_STRICT_KEY_CHECKING", "no");
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let decrypt_ctx = key_context(&home, ALICE_MEMBER_HANDLE);
    let signer_ctx = key_context(&home, BOB_MEMBER_HANDLE);
    let verified = file_artifact(&home, &signer_ctx, b"secret");
    remove_member(&workspace, BOB_MEMBER_HANDLE).unwrap();
    let evaluator = evaluator(&workspace);

    let error = evaluate_file_after_cli_review(
        &evaluator,
        &verified,
        &verified,
        &decrypt_ctx,
        &SignerTrustOutcome::Accepted,
        OperationOptions::default(),
    )
    .err()
    .expect("strict=no must preserve current-member enforcement");

    assert_eq!(error.rule(), Some("E_TRUST_NON_MEMBER"));
}

/// The trust gate a read runs under answers from the workspace the execution
/// bound to. A tree swapped in behind the workspace path lists the signer as an
/// active member again, and the read keeps refusing him as a non-member of the
/// tree it opened.
#[cfg(unix)]
#[test]
fn test_read_evaluator_keeps_the_member_set_of_the_bound_workspace() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::set_var("KAPSARO_STRICT_KEY_CHECKING", "no");
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let (_replacement_home, replacement) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let decrypt_ctx = key_context(&home, ALICE_MEMBER_HANDLE);
    let signer_ctx = key_context(&home, BOB_MEMBER_HANDLE);
    let verified = file_artifact(&home, &signer_ctx, b"secret");
    remove_member(&workspace, BOB_MEMBER_HANDLE).unwrap();
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, Some(&workspace));
    let opened_workspace = workspace.with_extension("opened");
    std::fs::rename(&workspace, &opened_workspace).unwrap();
    std::fs::rename(&replacement, &workspace).unwrap();

    let evaluator = resolve_read_trust_evaluator(&execution).unwrap();
    let error = evaluate_file_after_cli_review(
        &evaluator,
        &verified,
        &verified,
        &decrypt_ctx,
        &SignerTrustOutcome::Accepted,
        OperationOptions::default(),
    )
    .err()
    .expect("a signer removed from the bound workspace must stay a non-member");

    assert_eq!(error.rule(), Some("E_TRUST_NON_MEMBER"));
}

#[test]
fn test_non_member_allowance_rejects_changed_artifact() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::remove_var("KAPSARO_STRICT_KEY_CHECKING");
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let decrypt_ctx = key_context(&home, ALICE_MEMBER_HANDLE);
    let signer_ctx = key_context(&home, BOB_MEMBER_HANDLE);
    let reviewed = file_artifact(&home, &signer_ctx, b"reviewed");
    let current = file_artifact(&home, &signer_ctx, b"changed");
    remove_member(&workspace, BOB_MEMBER_HANDLE).unwrap();
    let evaluator = evaluator(&workspace);
    let outcome = non_member_outcome(&home, &signer_ctx);

    let error = evaluate_file_after_cli_review(
        &evaluator,
        &reviewed,
        &current,
        &decrypt_ctx,
        &outcome,
        OperationOptions::default(),
    )
    .err()
    .expect("non-member allowance must be artifact-bound");

    assert_eq!(error.rule(), Some("E_TRUST_TARGET_CHANGED"));
}

#[test]
fn test_accepted_non_member_same_artifact_returns_mac_verified_trusted_value() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::remove_var("KAPSARO_STRICT_KEY_CHECKING");
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let decrypt_ctx = key_context(&home, ALICE_MEMBER_HANDLE);
    let signer_ctx = key_context(&home, BOB_MEMBER_HANDLE);
    let verified = file_artifact(&home, &signer_ctx, b"secret");
    remove_member(&workspace, BOB_MEMBER_HANDLE).unwrap();
    let evaluator = evaluator(&workspace);

    let decision = evaluate_file_after_cli_review(
        &evaluator,
        &verified,
        &verified,
        &decrypt_ctx,
        &non_member_outcome(&home, &signer_ctx),
        OperationOptions::default(),
    )
    .unwrap();
    let TrustDecision::Trusted(trusted) = decision else {
        panic!("accepted exact non-member artifact must be trusted");
    };

    assert_eq!(trusted.decrypt_bytes().unwrap().expose_secret(), b"secret");
}

#[test]
fn test_normal_file_policy_rejects_changed_artifact() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::remove_var("KAPSARO_STRICT_KEY_CHECKING");
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let key_ctx = key_context(&home, ALICE_MEMBER_HANDLE);
    let reviewed = file_artifact(&home, &key_ctx, b"reviewed");
    let current = file_artifact(&home, &key_ctx, b"changed");

    let error = evaluate_file_after_cli_review(
        &evaluator(&workspace),
        &reviewed,
        &current,
        &key_ctx,
        &SignerTrustOutcome::Accepted,
        OperationOptions::default(),
    )
    .err()
    .expect("normal policy must bind review to the exact artifact");

    assert_eq!(error.rule(), Some("E_TRUST_TARGET_CHANGED"));
}

#[test]
fn test_normal_file_policy_accepts_same_artifact() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::remove_var("KAPSARO_STRICT_KEY_CHECKING");
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let key_ctx = key_context(&home, ALICE_MEMBER_HANDLE);
    let verified = file_artifact(&home, &key_ctx, b"same");

    let decision = evaluate_file_after_cli_review(
        &evaluator(&workspace),
        &verified,
        &verified,
        &key_ctx,
        &SignerTrustOutcome::Accepted,
        OperationOptions::default(),
    )
    .unwrap();

    assert!(matches!(decision, TrustDecision::Trusted(_)));
}

#[test]
fn test_normal_kv_policy_rejects_changed_artifact() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::remove_var("KAPSARO_STRICT_KEY_CHECKING");
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let key_ctx = key_context(&home, ALICE_MEMBER_HANDLE);
    let reviewed = kv_artifact(&home, &key_ctx, "reviewed");
    let current = kv_artifact(&home, &key_ctx, "changed");

    let error = evaluate_kv_after_cli_review(
        &evaluator(&workspace),
        &reviewed,
        &current,
        &key_ctx,
        KvReadOperation::Entries,
        &SignerTrustOutcome::Accepted,
        OperationOptions::default(),
    )
    .err()
    .expect("normal policy must bind review to the exact KV artifact");

    assert_eq!(error.rule(), Some("E_TRUST_TARGET_CHANGED"));
}

#[test]
fn test_normal_kv_policy_accepts_same_artifact() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::remove_var("KAPSARO_STRICT_KEY_CHECKING");
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let key_ctx = key_context(&home, ALICE_MEMBER_HANDLE);
    let verified = kv_artifact(&home, &key_ctx, "same");

    let decision = evaluate_kv_after_cli_review(
        &evaluator(&workspace),
        &verified,
        &verified,
        &key_ctx,
        KvReadOperation::Entries,
        &SignerTrustOutcome::Accepted,
        OperationOptions::default(),
    )
    .unwrap();

    assert!(matches!(decision, TrustDecision::Trusted(_)));
}

fn key_context(home: &tempfile::TempDir, member_handle: &str) -> KeyContext {
    KeyContext::from_inner(setup_member_key_context(home, member_handle, None))
}

fn file_artifact(
    home: &tempfile::TempDir,
    signer_ctx: &KeyContext,
    plaintext: &[u8],
) -> VerifiedFileEncArtifact {
    let recipients = LocalKeyStore::open(home.path().join("keys"))
        .expect("open keystore")
        .load_recipient_keys([member_handle(ALICE_MEMBER_HANDLE)])
        .unwrap();
    FileEncArtifact::encrypt_bytes(plaintext, &recipients, signer_ctx)
        .unwrap()
        .verify(OperationOptions::default())
        .unwrap()
}

fn kv_artifact(
    home: &tempfile::TempDir,
    signer_ctx: &KeyContext,
    value: &str,
) -> VerifiedKvEncArtifact {
    let recipients = LocalKeyStore::open(home.path().join("keys"))
        .expect("open keystore")
        .load_recipient_keys([member_handle(ALICE_MEMBER_HANDLE)])
        .unwrap();
    KvEncArtifact::encrypt_entries(
        vec![KvInputEntry::new(
            "KEY",
            SecretString::new(value.to_string()),
        )],
        &recipients,
        signer_ctx,
    )
    .unwrap()
    .verify(OperationOptions::default())
    .unwrap()
}

fn evaluator(workspace: &std::path::Path) -> TrustPolicyEvaluator {
    TrustPolicyEvaluator::new(CurrentMemberSnapshot::load(workspace).unwrap(), None)
}

fn non_member_outcome(home: &tempfile::TempDir, signer_ctx: &KeyContext) -> SignerTrustOutcome {
    let key_store = home.path().join("keys");
    let kid = signer_ctx.kid();
    let public_key = load_public_key(&key_store, BOB_MEMBER_HANDLE, kid).unwrap();
    SignerTrustOutcome::NeedsNonMemberAcceptance {
        candidate: TrustApprovalCandidateBuilder::from_public_key(&public_key).build(),
        current_recipients: vec![ALICE_MEMBER_HANDLE.to_string()],
    }
}
