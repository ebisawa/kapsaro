// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for operation-bound authorized KV mutations.
//! Ensures operation binding and exact active-member recipient authorization.

use super::{KvEncArtifact, KvInputEntry, KvMutationOperation};
use crate::api::key::{KeyContext, LocalKeyStore, MemberHandle};
use crate::api::operation::OperationOptions;
use crate::api::secret::SecretString;
use crate::api::trust::{
    ApprovalConflictHandling, CurrentMemberSnapshot, KnownKeyApprovalEvidence, LocalTrustStore,
    TrustApproval, TrustDecision, TrustPolicyEvaluator, TrustRecipientHandleHint, TrustReviewKind,
    TrustReviewRequest,
};
use crate::test_utils::{setup_member_key_context, setup_test_workspace_from_fixtures};

const ALICE_MEMBER_HANDLE: &str = "alice@example.com";
const BOB_MEMBER_HANDLE: &str = "bob@example.com";

fn member_handle(value: &str) -> MemberHandle {
    MemberHandle::try_from(value).expect("valid member handle")
}

fn approval_from_request(request: &TrustReviewRequest) -> crate::Result<TrustApproval> {
    match request.kind() {
        TrustReviewKind::KnownKey => TrustApproval::known_key(
            request
                .known_key_candidate()
                .expect("known-key review carries its verified candidate"),
            KnownKeyApprovalEvidence::none(),
        ),
        TrustReviewKind::RecipientSet | TrustReviewKind::ChangedRecipientSet => {
            TrustApproval::recipient_set(
                request.sid().expect("recipient review carries sid"),
                request.recipient_kids().to_vec(),
                request.recipient_handle_hints().to_vec(),
            )
        }
    }
}

/// A kv-enc document is bounded by the same limit however it was produced. A
/// write allowed past it would build a document that no later read accepts,
/// leaving the entries in a file the operator can no longer open.
#[test]
fn test_encrypt_entries_rejects_a_document_past_the_size_limit() {
    let (temp_dir, _workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let key_ctx = KeyContext::from_inner(setup_member_key_context(
        &temp_dir,
        ALICE_MEMBER_HANDLE,
        None,
    ));
    let recipients = LocalKeyStore::open(temp_dir.path().join("keys"))
        .expect("open keystore")
        .load_recipient_keys([member_handle(ALICE_MEMBER_HANDLE)])
        .unwrap();
    let entries = (0..24)
        .map(|index| {
            KvInputEntry::new(
                format!("KEY{index}"),
                SecretString::new("v".repeat(700_000)),
            )
        })
        .collect::<Vec<_>>();

    let error = KvEncArtifact::encrypt_entries(entries, &recipients, &key_ctx)
        .expect_err("entries past the document limit must be refused");

    assert!(
        error
            .format_user_message()
            .contains("exceeds maximum size limit"),
        "{}",
        error.format_user_message()
    );
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
        .any(|hint| hint.recipient_handle().as_str() == BOB_MEMBER_HANDLE));

    let missing_hint = recipient_request.recipient_handle_hints()[1..].to_vec();
    assert!(TrustApproval::recipient_set(
        recipient_request
            .sid()
            .expect("recipient review carries sid"),
        recipient_request.recipient_kids().to_vec(),
        missing_hint,
    )
    .is_err());

    let duplicate_hint = vec![
        recipient_request.recipient_handle_hints()[0].clone(),
        recipient_request.recipient_handle_hints()[0].clone(),
    ];
    assert!(TrustApproval::recipient_set(
        recipient_request
            .sid()
            .expect("recipient review carries sid"),
        recipient_request.recipient_kids().to_vec(),
        duplicate_hint,
    )
    .is_err());

    let extra_hint = recipient_request.recipient_handle_hints().to_vec();
    assert!(TrustApproval::recipient_set(
        recipient_request
            .sid()
            .expect("recipient review carries sid"),
        recipient_request.recipient_kids()[..1].to_vec(),
        extra_hint,
    )
    .is_err());

    let outsider_hint = vec![
        recipient_request.recipient_handle_hints()[0].clone(),
        TrustRecipientHandleHint::for_test("KCD3AAAA1111BBBB2222CCCC3333DDDD", "carol@example.com"),
    ];
    assert!(TrustApproval::recipient_set(
        recipient_request
            .sid()
            .expect("recipient review carries sid"),
        recipient_request.recipient_kids().to_vec(),
        outsider_hint,
    )
    .is_err());
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
        .map(approval_from_request)
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
        .map(approval_from_request)
        .collect::<crate::Result<Vec<_>>>()
        .unwrap();
    approvals.push(TrustApproval::recipient_set_for_test(
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

    let changed = requests
        .iter()
        .find(|request| request.kind() == TrustReviewKind::ChangedRecipientSet)
        .expect("the changed recipient set must be reviewed");
    let approved = changed
        .approved_recipient_set()
        .expect("a changed recipient set names the set approved before it");
    assert_eq!(
        approved.recipient_kids,
        vec![input_recipients.keys()[0].document().protected.kid.clone()]
    );
    let mut reviewed_kids = changed
        .recipient_kids()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let mut output_kids = output_recipients
        .keys()
        .iter()
        .map(|key| key.document().protected.kid.clone())
        .collect::<Vec<_>>();
    reviewed_kids.sort();
    output_kids.sort();
    assert_eq!(reviewed_kids, output_kids);
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
            vec![TrustApproval::known_key_for_test(
                ALICE_MEMBER_HANDLE,
                alice_kid,
            )],
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
