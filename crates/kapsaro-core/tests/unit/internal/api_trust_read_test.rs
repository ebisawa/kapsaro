// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Read trust-gate tests for operation-bound public artifact facades.
//! Covers current-member authorization, review requests, and trusted reads.

use crate::api::file::{FileEncArtifact, FileReadOperation};
use crate::api::key::{KeyContext, LocalKeyStore};
use crate::api::kv::{KvEncArtifact, KvInputEntry, KvReadOperation};
use crate::api::operation::OperationOptions;
use crate::api::secret::SecretString;
use crate::api::trust::{
    ApprovalConflictHandling, CurrentMemberSnapshot, LocalTrustStore, TrustApproval, TrustDecision,
    TrustPolicyEvaluator, TrustReviewKind,
};
use crate::cli_api::test_support::storage::trust::store::save_trust_store;
use crate::feature::trust::signature::sign_trust_store;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::io::workspace::members::test_support::remove_active_member as remove_member;
use crate::model::trust_store::TrustStoreProtected;
use crate::model::wire::format::LOCAL_TRUST_V1;
use crate::test_utils::{
    member_handle, setup_member_key_context, setup_test_workspace_from_fixtures,
    ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE,
};

fn load_key_context(home: &tempfile::TempDir, member_handle: &str) -> KeyContext {
    KeyContext::from_inner(setup_member_key_context(home, member_handle, None))
}

fn load_file_artifact(
    home: &tempfile::TempDir,
    signer: &str,
    recipients: &[&str],
) -> (FileEncArtifact, KeyContext) {
    let key_store = LocalKeyStore::open(home.path().join("keys")).expect("open keystore");
    let signer_ctx = load_key_context(home, signer);
    let recipient_keys = key_store
        .load_recipient_keys(recipients.iter().map(|value| member_handle(*value)))
        .expect("load recipient keys");
    let artifact = FileEncArtifact::encrypt_bytes(b"secret", &recipient_keys, &signer_ctx)
        .expect("encrypt file artifact");
    (artifact, signer_ctx)
}

#[test]
fn test_evaluate_file_self_artifact_trusted() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let (artifact, _signer_ctx) =
        load_file_artifact(&home, ALICE_MEMBER_HANDLE, &[ALICE_MEMBER_HANDLE]);
    let verified = artifact
        .verify(OperationOptions::default())
        .expect("verify artifact");
    let decrypt_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let evaluator = TrustPolicyEvaluator::new(
        CurrentMemberSnapshot::load(&workspace).expect("load members"),
        None,
    );

    let decision = evaluator
        .evaluate_file(
            &verified,
            &decrypt_ctx,
            FileReadOperation::Decrypt,
            OperationOptions::default(),
        )
        .expect("evaluate trust");

    let TrustDecision::Trusted(trusted) = decision else {
        panic!("self artifact must be trusted");
    };
    assert_eq!(trusted.decrypt_bytes().unwrap().expose_secret(), b"secret");
}

#[test]
fn test_evaluate_file_current_unknown_signer_requires_review() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let (artifact, _signer_ctx) =
        load_file_artifact(&home, BOB_MEMBER_HANDLE, &[ALICE_MEMBER_HANDLE]);
    let verified = artifact
        .verify(OperationOptions::default())
        .expect("verify artifact");
    let decrypt_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let evaluator = TrustPolicyEvaluator::new(
        CurrentMemberSnapshot::load(&workspace).expect("load members"),
        None,
    );

    let decision = evaluator
        .evaluate_file(
            &verified,
            &decrypt_ctx,
            FileReadOperation::Decrypt,
            OperationOptions::default(),
        )
        .expect("evaluate trust");

    let TrustDecision::ReviewRequired(requests) = decision else {
        panic!("unknown current signer must require review");
    };
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].kind(), TrustReviewKind::KnownKey);
    assert_eq!(requests[0].subject_handle(), Some(BOB_MEMBER_HANDLE));
}

#[test]
fn test_evaluate_file_known_current_signer_trusted() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let (artifact, _signer_ctx) =
        load_file_artifact(&home, BOB_MEMBER_HANDLE, &[ALICE_MEMBER_HANDLE]);
    let verified = artifact
        .verify(OperationOptions::default())
        .expect("verify artifact");
    let decrypt_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let key_store = LocalKeyStore::open(home.path().join("keys")).expect("open keystore");
    let bob_kid = key_store
        .list_kids(&member_handle(BOB_MEMBER_HANDLE))
        .expect("list member kids")
        .into_iter()
        .next()
        .expect("member kid");
    let trust_store = LocalTrustStore::open(home.path(), member_handle(ALICE_MEMBER_HANDLE))
        .expect("open trust store");
    trust_store
        .apply_approvals_with_conflict_handling(
            vec![TrustApproval::known_key(BOB_MEMBER_HANDLE, bob_kid)],
            &decrypt_ctx,
            ApprovalConflictHandling::merge(),
        )
        .expect("approve signer");
    let verified_store = trust_store
        .load_verified(&key_store)
        .expect("load trust store")
        .expect("trust store exists")
        .into_store();
    let evaluator = TrustPolicyEvaluator::new(
        CurrentMemberSnapshot::load(&workspace).expect("load members"),
        Some(verified_store),
    );

    let decision = evaluator
        .evaluate_file(
            &verified,
            &decrypt_ctx,
            FileReadOperation::Decrypt,
            OperationOptions::default(),
        )
        .expect("evaluate trust");

    assert!(matches!(decision, TrustDecision::Trusted(_)));
}

#[test]
fn test_evaluate_file_non_member_signer_error() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let (artifact, _signer_ctx) =
        load_file_artifact(&home, BOB_MEMBER_HANDLE, &[ALICE_MEMBER_HANDLE]);
    remove_member(&workspace, BOB_MEMBER_HANDLE).expect("remove current member");
    let verified = artifact
        .verify(OperationOptions::default())
        .expect("verify artifact");
    let decrypt_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let evaluator = TrustPolicyEvaluator::new(
        CurrentMemberSnapshot::load(&workspace).expect("load members"),
        None,
    );

    let error = evaluator
        .evaluate_file(
            &verified,
            &decrypt_ctx,
            FileReadOperation::Decrypt,
            OperationOptions::default(),
        )
        .err()
        .expect("non-member signer must fail closed");

    assert_eq!(error.rule(), Some("E_TRUST_NON_MEMBER"));
}

#[test]
fn test_evaluate_kv_self_artifact_trusted_for_bound_list() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let key_store = LocalKeyStore::open(home.path().join("keys")).expect("open keystore");
    let key_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let recipients = key_store
        .load_recipient_keys([member_handle(ALICE_MEMBER_HANDLE)])
        .expect("load recipients");
    let artifact = KvEncArtifact::encrypt_entries(
        vec![KvInputEntry::new(
            "API_KEY",
            SecretString::new("secret".to_string()),
        )],
        &recipients,
        &key_ctx,
    )
    .expect("encrypt KV artifact");
    let verified = artifact
        .verify(OperationOptions::default())
        .expect("verify artifact");
    let evaluator = TrustPolicyEvaluator::new(
        CurrentMemberSnapshot::load(&workspace).expect("load members"),
        None,
    );

    let decision = evaluator
        .evaluate_kv(
            &verified,
            &key_ctx,
            KvReadOperation::List,
            OperationOptions::default(),
        )
        .expect("evaluate trust");

    let TrustDecision::Trusted(trusted) = decision else {
        panic!("self artifact must be trusted");
    };
    let entries = trusted.list_entry_keys().expect("list trusted keys");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key(), "API_KEY");
    let error = trusted
        .decrypt_entries()
        .expect_err("list authorization must not permit value reads");
    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
}

#[test]
fn test_evaluate_kv_non_member_signer_hides_keys() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let key_store = LocalKeyStore::open(home.path().join("keys")).expect("open keystore");
    let signer_ctx = load_key_context(&home, BOB_MEMBER_HANDLE);
    let decrypt_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let recipients = key_store
        .load_recipient_keys([member_handle(ALICE_MEMBER_HANDLE)])
        .expect("load recipients");
    let artifact = KvEncArtifact::encrypt_entries(
        vec![KvInputEntry::new(
            "HIDDEN_KEY",
            SecretString::new("secret".to_string()),
        )],
        &recipients,
        &signer_ctx,
    )
    .expect("encrypt KV artifact");
    remove_member(&workspace, BOB_MEMBER_HANDLE).expect("remove current signer");
    let verified = artifact
        .verify(OperationOptions::default())
        .expect("cryptographic signature remains valid");
    let evaluator = TrustPolicyEvaluator::new(
        CurrentMemberSnapshot::load(&workspace).expect("load members"),
        None,
    );

    let error = evaluator
        .evaluate_kv(
            &verified,
            &decrypt_ctx,
            KvReadOperation::List,
            OperationOptions::default(),
        )
        .err()
        .expect("non-member signer must fail before key listing");

    assert_eq!(error.rule(), Some("E_TRUST_NON_MEMBER"));
}

#[test]
fn test_evaluate_kv_current_recipient_key_requires_review() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let key_store = LocalKeyStore::open(home.path().join("keys")).expect("open keystore");
    let key_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let recipients = key_store
        .load_recipient_keys([
            member_handle(ALICE_MEMBER_HANDLE),
            member_handle(BOB_MEMBER_HANDLE),
        ])
        .expect("load recipients");
    let artifact = KvEncArtifact::encrypt_entries(
        vec![KvInputEntry::new(
            "API_KEY",
            SecretString::new("secret".to_string()),
        )],
        &recipients,
        &key_ctx,
    )
    .expect("encrypt KV artifact");
    let verified = artifact
        .verify(OperationOptions::default())
        .expect("verify artifact");
    let evaluator = TrustPolicyEvaluator::new(
        CurrentMemberSnapshot::load(&workspace).expect("load members"),
        None,
    );

    let decision = evaluator
        .evaluate_kv(
            &verified,
            &key_ctx,
            KvReadOperation::List,
            OperationOptions::default(),
        )
        .expect("evaluate trust");

    let TrustDecision::ReviewRequired(requests) = decision else {
        panic!("unknown current recipient key must require review");
    };
    assert!(requests.iter().any(|request| {
        request.kind() == TrustReviewKind::KnownKey
            && request.subject_handle() == Some(BOB_MEMBER_HANDLE)
    }));
}

#[test]
fn test_load_verified_without_keystore_reports_missing_local_keystore() {
    let home = crate::test_utils::setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let key_ctx = setup_member_key_context(&home, ALICE_MEMBER_HANDLE, None);
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: ALICE_MEMBER_HANDLE.to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
        known_keys: Vec::new(),
        recipient_sets: Vec::new(),
    };
    let document = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();
    save_trust_store(
        &get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE)),
        &document,
    )
    .unwrap();
    std::fs::remove_dir_all(home.path().join("keys")).unwrap();
    let trust_store =
        LocalTrustStore::open(home.path(), member_handle(ALICE_MEMBER_HANDLE)).unwrap();

    let error = match trust_store.load_verified_with_access(None) {
        Err(error) => error,
        Ok(_) => panic!("a trust document without a verification keystore must fail"),
    };

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some("E_LOCAL_KEYSTORE_MISSING"));
    let message = error.format_user_message();
    assert!(message.contains(&home.path().join("keys").display().to_string()));
    assert!(message.contains("--home"));
    assert!(message.contains("KAPSARO_HOME"));
}
