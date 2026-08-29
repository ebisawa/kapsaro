// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for operation-bound authorized KV mutations.
//! Ensures operation binding and exact active-member recipient authorization.

use super::{KvEncArtifact, KvInputEntry, KvMutationOperation};
use crate::api::key::{KeyContext, LocalKeyStore, MemberHandle};
use crate::api::operation::OperationOptions;
use crate::api::secret::SecretString;
use crate::api::trust::{
    ApprovalConflictHandling, CurrentMemberSnapshot, LocalTrustStore, TrustApproval, TrustDecision,
    TrustPolicyEvaluator, TrustReviewKind,
};
use crate::test_utils::{setup_member_key_context, setup_test_workspace_from_fixtures};

const ALICE_MEMBER_HANDLE: &str = "alice@example.com";
const BOB_MEMBER_HANDLE: &str = "bob@example.com";

fn member_handle(value: &str) -> MemberHandle {
    MemberHandle::try_from(value).expect("valid member handle")
}

#[test]
fn test_authorized_kv_set_mutation_binds_operation() {
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let key_ctx = KeyContext::from_inner(setup_member_key_context(
        &temp_dir,
        ALICE_MEMBER_HANDLE,
        None,
    ));
    let recipients = LocalKeyStore::open(temp_dir.path().join("keys"))
        .expect("open keystore")
        .load_recipient_keys([member_handle(ALICE_MEMBER_HANDLE)])
        .unwrap();
    let artifact = KvEncArtifact::encrypt_entries(
        vec![KvInputEntry::new(
            "KEY1",
            SecretString::new("value1".to_string()),
        )],
        &recipients,
        &key_ctx,
    )
    .unwrap();
    let verified = artifact.verify(OperationOptions::default()).unwrap();
    let members = CurrentMemberSnapshot::load(&workspace_dir).unwrap();
    let evaluator = TrustPolicyEvaluator::new(members, None);
    let decision = evaluator
        .evaluate_kv_mutation(
            &verified,
            &recipients,
            &key_ctx,
            KvMutationOperation::Set,
            OperationOptions::default(),
        )
        .unwrap();
    let TrustDecision::Trusted(authorized) = decision else {
        panic!("self-only KV mutation must be trusted");
    };

    authorized
        .set_entries(vec![KvInputEntry::new(
            "KEY2",
            SecretString::new("value2".to_string()),
        )])
        .unwrap();
    let error = authorized
        .unset_entry("KEY1")
        .expect_err("set authorization must not authorize unset");

    assert!(error
        .to_string()
        .contains("not authorized for unset mutations"));
}

#[test]
fn test_evaluate_kv_mutation_requires_output_recipient_reviews() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let key_ctx = KeyContext::from_inner(setup_member_key_context(
        &temp_dir,
        ALICE_MEMBER_HANDLE,
        None,
    ));
    let key_store = LocalKeyStore::open(temp_dir.path().join("keys")).expect("open keystore");
    let input_recipients = key_store
        .load_recipient_keys([member_handle(ALICE_MEMBER_HANDLE)])
        .unwrap();
    let output_recipients = key_store
        .load_recipient_keys([
            member_handle(BOB_MEMBER_HANDLE),
            member_handle(ALICE_MEMBER_HANDLE),
        ])
        .unwrap();
    let artifact = KvEncArtifact::encrypt_entries(
        vec![KvInputEntry::new(
            "KEY1",
            SecretString::new("value1".to_string()),
        )],
        &input_recipients,
        &key_ctx,
    )
    .unwrap();
    let verified = artifact.verify(OperationOptions::default()).unwrap();
    let evaluator =
        TrustPolicyEvaluator::new(CurrentMemberSnapshot::load(&workspace_dir).unwrap(), None);

    let decision = evaluator
        .evaluate_kv_mutation(
            &verified,
            &output_recipients,
            &key_ctx,
            KvMutationOperation::Set,
            OperationOptions::default(),
        )
        .unwrap();
    let TrustDecision::ReviewRequired(requests) = decision else {
        panic!("unapproved output recipient keys must require review");
    };

    assert!(requests
        .iter()
        .any(|request| request.kind() == TrustReviewKind::KnownKey));
    assert!(requests
        .iter()
        .any(|request| request.kind() == TrustReviewKind::RecipientSet));
    let recipient_request = requests
        .iter()
        .find(|request| request.kind() == TrustReviewKind::RecipientSet)
        .unwrap();
    assert_eq!(recipient_request.recipient_handle_hints().len(), 2);
    assert!(recipient_request
        .recipient_handle_hints()
        .iter()
        .any(|hint| hint.recipient_handle() == BOB_MEMBER_HANDLE));
}

#[test]
fn test_evaluate_kv_mutation_accepts_approved_output_recipient_set_and_persists_hints() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let key_ctx = KeyContext::from_inner(setup_member_key_context(
        &temp_dir,
        ALICE_MEMBER_HANDLE,
        None,
    ));
    let key_store = LocalKeyStore::open(temp_dir.path().join("keys")).expect("open keystore");
    let input_recipients = key_store
        .load_recipient_keys([member_handle(ALICE_MEMBER_HANDLE)])
        .unwrap();
    let output_recipients = key_store
        .load_recipient_keys([
            member_handle(BOB_MEMBER_HANDLE),
            member_handle(ALICE_MEMBER_HANDLE),
        ])
        .unwrap();
    let artifact = KvEncArtifact::encrypt_entries(
        vec![KvInputEntry::new(
            "KEY1",
            SecretString::new("value1".to_string()),
        )],
        &input_recipients,
        &key_ctx,
    )
    .unwrap();
    let verified = artifact.verify(OperationOptions::default()).unwrap();
    let members = CurrentMemberSnapshot::load(&workspace_dir).unwrap();
    let TrustDecision::ReviewRequired(requests) = TrustPolicyEvaluator::new(members.clone(), None)
        .evaluate_kv_mutation(
            &verified,
            &output_recipients,
            &key_ctx,
            KvMutationOperation::Set,
            OperationOptions::default(),
        )
        .unwrap()
    else {
        panic!("new recipient keys and set must require review");
    };
    let approvals = requests
        .iter()
        .map(TrustApproval::from_request)
        .collect::<crate::Result<Vec<_>>>()
        .unwrap();
    let trust_store = LocalTrustStore::open(temp_dir.path(), member_handle(ALICE_MEMBER_HANDLE))
        .expect("open trust store");
    trust_store
        .apply_approvals_with_conflict_handling(
            approvals,
            &key_ctx,
            ApprovalConflictHandling::merge(),
        )
        .unwrap();
    let store = trust_store
        .load_verified(&key_store)
        .unwrap()
        .unwrap()
        .into_store();

    let decision = TrustPolicyEvaluator::new(members, Some(store))
        .evaluate_kv_mutation(
            &verified,
            &output_recipients,
            &key_ctx,
            KvMutationOperation::Set,
            OperationOptions::default(),
        )
        .unwrap();

    assert!(matches!(decision, TrustDecision::Trusted(_)));
    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(trust_store.path()).unwrap()).unwrap();
    let hints = saved["protected"]["recipient_sets"][0]["recipient_handle_hints"]
        .as_array()
        .unwrap();
    assert!(hints
        .iter()
        .any(|hint| hint["recipient_handle"] == BOB_MEMBER_HANDLE));
}

#[test]
fn test_evaluate_kv_mutation_requires_review_for_changed_output_recipient_set() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let key_ctx = KeyContext::from_inner(setup_member_key_context(
        &temp_dir,
        ALICE_MEMBER_HANDLE,
        None,
    ));
    let key_store = LocalKeyStore::open(temp_dir.path().join("keys")).expect("open keystore");
    let input_recipients = key_store
        .load_recipient_keys([member_handle(ALICE_MEMBER_HANDLE)])
        .unwrap();
    let output_recipients = key_store
        .load_recipient_keys([
            member_handle(ALICE_MEMBER_HANDLE),
            member_handle(BOB_MEMBER_HANDLE),
        ])
        .unwrap();
    let artifact = KvEncArtifact::encrypt_entries(
        vec![KvInputEntry::new(
            "KEY1",
            SecretString::new("value1".to_string()),
        )],
        &input_recipients,
        &key_ctx,
    )
    .unwrap();
    let verified = artifact.verify(OperationOptions::default()).unwrap();
    let members = CurrentMemberSnapshot::load(&workspace_dir).unwrap();
    let TrustDecision::ReviewRequired(initial_requests) =
        TrustPolicyEvaluator::new(members.clone(), None)
            .evaluate_kv_mutation(
                &verified,
                &output_recipients,
                &key_ctx,
                KvMutationOperation::Set,
                OperationOptions::default(),
            )
            .unwrap()
    else {
        panic!("new recipient keys and set must require review");
    };
    let mut approvals = initial_requests
        .iter()
        .filter(|request| request.kind() == TrustReviewKind::KnownKey)
        .map(TrustApproval::from_request)
        .collect::<crate::Result<Vec<_>>>()
        .unwrap();
    approvals.push(TrustApproval::recipient_set(
        verified.recipient_set_subject().unwrap().sid(),
        vec![input_recipients.keys()[0].document().protected.kid.clone()],
    ));
    let trust_store = LocalTrustStore::open(temp_dir.path(), member_handle(ALICE_MEMBER_HANDLE))
        .expect("open trust store");
    trust_store
        .apply_approvals_with_conflict_handling(
            approvals,
            &key_ctx,
            ApprovalConflictHandling::merge(),
        )
        .unwrap();
    let store = trust_store
        .load_verified(&key_store)
        .unwrap()
        .unwrap()
        .into_store();

    let decision = TrustPolicyEvaluator::new(members, Some(store))
        .evaluate_kv_mutation(
            &verified,
            &output_recipients,
            &key_ctx,
            KvMutationOperation::Set,
            OperationOptions::default(),
        )
        .unwrap();
    let TrustDecision::ReviewRequired(requests) = decision else {
        panic!("changed recipient set must require review");
    };

    assert!(requests
        .iter()
        .any(|request| request.kind() == TrustReviewKind::ChangedRecipientSet));
}

#[test]
fn test_evaluate_kv_mutation_rejects_store_owner_before_recipient_lookup() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let alice_ctx = KeyContext::from_inner(setup_member_key_context(
        &temp_dir,
        ALICE_MEMBER_HANDLE,
        None,
    ));
    let bob_ctx =
        KeyContext::from_inner(setup_member_key_context(&temp_dir, BOB_MEMBER_HANDLE, None));
    let key_store = LocalKeyStore::open(temp_dir.path().join("keys")).expect("open keystore");
    let recipients = key_store
        .load_recipient_keys([member_handle(ALICE_MEMBER_HANDLE)])
        .unwrap();
    let artifact = KvEncArtifact::encrypt_entries(
        vec![KvInputEntry::new(
            "KEY1",
            SecretString::new("value1".to_string()),
        )],
        &recipients,
        &alice_ctx,
    )
    .unwrap();
    let verified = artifact.verify(OperationOptions::default()).unwrap();
    let trust_store = LocalTrustStore::open(temp_dir.path(), member_handle(BOB_MEMBER_HANDLE))
        .expect("open trust store");
    let alice_kid = key_store
        .list_kids(&member_handle(ALICE_MEMBER_HANDLE))
        .expect("list alice kids")
        .into_iter()
        .next()
        .expect("alice kid must exist")
        .into_string();
    trust_store
        .apply_approvals_with_conflict_handling(
            vec![TrustApproval::known_key(ALICE_MEMBER_HANDLE, alice_kid)],
            &bob_ctx,
            ApprovalConflictHandling::merge(),
        )
        .unwrap();
    let store = trust_store
        .load_verified(&key_store)
        .unwrap()
        .unwrap()
        .into_store();
    let evaluator = TrustPolicyEvaluator::new(
        CurrentMemberSnapshot::load(&workspace_dir).unwrap(),
        Some(store),
    );

    let error = evaluator
        .evaluate_kv_mutation(
            &verified,
            &recipients,
            &alice_ctx,
            KvMutationOperation::Set,
            OperationOptions::default(),
        )
        .err()
        .expect("owner mismatch must be rejected before recipient-set lookup");

    assert!(error
        .to_string()
        .contains("does not match key context member_handle"));
}

#[test]
fn test_evaluate_kv_mutation_output_recipient_subset_error() {
    let (temp_dir, workspace_dir) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let key_ctx = KeyContext::from_inner(setup_member_key_context(
        &temp_dir,
        ALICE_MEMBER_HANDLE,
        None,
    ));
    let recipients = LocalKeyStore::open(temp_dir.path().join("keys"))
        .expect("open keystore")
        .load_recipient_keys([member_handle(ALICE_MEMBER_HANDLE)])
        .unwrap();
    let artifact = KvEncArtifact::encrypt_entries(
        vec![KvInputEntry::new(
            "KEY1",
            SecretString::new("value1".to_string()),
        )],
        &recipients,
        &key_ctx,
    )
    .unwrap();
    let verified = artifact.verify(OperationOptions::default()).unwrap();
    let evaluator =
        TrustPolicyEvaluator::new(CurrentMemberSnapshot::load(&workspace_dir).unwrap(), None);

    let error = match evaluator.evaluate_kv_mutation(
        &verified,
        &recipients,
        &key_ctx,
        KvMutationOperation::Set,
        OperationOptions::default(),
    ) {
        Err(error) => error,
        Ok(_) => panic!("output recipients must include every active member"),
    };

    assert_eq!(error.rule(), Some("E_TRUST_REJECTED"));
}
