// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Read trust-gate tests for operation-bound public artifact facades.
//! Covers current-member authorization, review requests, and trusted reads.

use crate::api::file::{FileEncArtifact, FileReadOperation};
use crate::api::key::{KeyContext, Kid, LocalKeyStore};
use crate::api::kv::{KvEncArtifact, KvInputEntry, KvReadOperation};
use crate::api::operation::OperationOptions;
use crate::api::secret::SecretString;
use crate::api::trust::{
    ApprovalConflictHandling, CurrentMemberSnapshot, KnownKeyApprovalEvidence, KnownKeyReview,
    LocalTrustStore, ReadTrustExceptions, TrustApproval, TrustDecision, TrustPolicyEvaluator,
    TrustReviewKind,
};
use crate::cli_api::test_support::storage::trust::store::save_trust_store;
use crate::feature::trust::recipient_sets::ArtifactRecipientSet;
use crate::feature::trust::signature::sign_trust_store;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::io::workspace::members::load_active_member_files;
use crate::io::workspace::members::test_support::remove_active_member as remove_member;
use crate::model::trust_store::{RecipientHandleHint, TrustStoreProtected};
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
fn test_output_recipient_preflight_rejects_non_known_key_approval() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let recipients = load_active_member_files(&workspace).expect("load active recipients");
    let evaluator = TrustPolicyEvaluator::new(
        CurrentMemberSnapshot::load(&workspace).expect("load members"),
        None,
    );
    let key_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let self_trust = super::build_self_trust(&key_ctx).expect("build self trust");
    let approval = TrustApproval::recipient_set_for_test(
        uuid::Uuid::new_v4(),
        vec![recipients[0].protected.kid.clone()],
    );

    let error = evaluator
        .preflight_output_recipient_keys(&recipients, &self_trust, &[approval])
        .unwrap_err();

    assert!(error.to_string().contains("require known-key approvals"));
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
            ReadTrustExceptions::none(),
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
            ReadTrustExceptions::none(),
        )
        .expect("evaluate trust");

    let TrustDecision::ReviewRequired(requests) = decision else {
        panic!("unknown current signer must require review");
    };
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].kind(), TrustReviewKind::KnownKey);
    assert_eq!(
        requests[0].subject_handle().map(|handle| handle.as_str()),
        Some(BOB_MEMBER_HANDLE)
    );
    assert!(requests[0].known_key_candidate().is_some());
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
    let initial = TrustPolicyEvaluator::new(
        CurrentMemberSnapshot::load(&workspace).expect("load members"),
        None,
    )
    .evaluate_file(
        &verified,
        &decrypt_ctx,
        FileReadOperation::Decrypt,
        OperationOptions::default(),
        ReadTrustExceptions::none(),
    )
    .expect("request signer review");
    let TrustDecision::ReviewRequired(requests) = initial else {
        panic!("unknown signer must require review");
    };
    let candidate = requests[0]
        .known_key_candidate()
        .expect("known-key review candidate");
    let approval = TrustApproval::known_key(candidate, KnownKeyApprovalEvidence::none())
        .expect("approve candidate without GitHub binding");
    let trust_store = LocalTrustStore::open(home.path(), member_handle(ALICE_MEMBER_HANDLE))
        .expect("open trust store");
    trust_store
        .apply_approvals_with_conflict_handling(
            vec![approval],
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
            ReadTrustExceptions::none(),
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
            ReadTrustExceptions::none(),
        )
        .err()
        .expect("non-member signer must fail closed");

    assert_eq!(error.rule(), Some("E_TRUST_NON_MEMBER"));
}

#[test]
fn test_evaluate_file_skips_only_known_key_review() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let (artifact, _signer_ctx) =
        load_file_artifact(&home, BOB_MEMBER_HANDLE, &[ALICE_MEMBER_HANDLE]);
    let verified = artifact.verify(OperationOptions::default()).unwrap();
    let decrypt_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let evaluator =
        TrustPolicyEvaluator::new(CurrentMemberSnapshot::load(&workspace).unwrap(), None);

    let decision = evaluator
        .evaluate_file(
            &verified,
            &decrypt_ctx,
            FileReadOperation::Decrypt,
            OperationOptions::default(),
            ReadTrustExceptions::none().with_known_key_review(KnownKeyReview::Skipped),
        )
        .unwrap();

    assert!(matches!(decision, TrustDecision::Trusted(_)));
}

#[test]
fn test_preflight_file_read_keeps_unresolved_recipient_kids_when_review_is_skipped() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let (artifact, _signer_ctx) = load_file_artifact(
        &home,
        ALICE_MEMBER_HANDLE,
        &[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE],
    );
    let key_store = LocalKeyStore::open(home.path().join("keys")).unwrap();
    let bob_kid = key_store
        .list_kids(&member_handle(BOB_MEMBER_HANDLE))
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    remove_member(&workspace, BOB_MEMBER_HANDLE).unwrap();
    let verified = artifact.verify(OperationOptions::default()).unwrap();
    let decrypt_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let evaluator =
        TrustPolicyEvaluator::new(CurrentMemberSnapshot::load(&workspace).unwrap(), None);

    let review = evaluator
        .preflight_file_read(&verified, &decrypt_ctx, KnownKeyReview::Skipped, false)
        .unwrap();

    assert!(review.requests().is_empty());
    assert_eq!(review.unresolved_recipient_kids(), &[bob_kid]);
}

#[test]
fn test_active_recipient_kid_rejects_mismatched_handle_hint() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let key_store = LocalKeyStore::open(home.path().join("keys")).unwrap();
    let alice_kid = key_store
        .list_kids(&member_handle(ALICE_MEMBER_HANDLE))
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let recipient_set = ArtifactRecipientSet::from_parts(
        uuid::Uuid::new_v4(),
        vec![alice_kid.to_string()],
        vec![RecipientHandleHint {
            kid: alice_kid.to_string(),
            recipient_handle: BOB_MEMBER_HANDLE.to_string(),
        }],
    )
    .unwrap();
    let subject = super::RecipientSetSubject::from_inner(recipient_set).unwrap();
    let evaluator = TrustPolicyEvaluator::new(
        CurrentMemberSnapshot::load(&workspace).expect("load members"),
        None,
    );

    let error = evaluator
        .enforce_artifact_recipients_current(&subject)
        .expect_err("an active kid with a different handle must be rejected");

    assert_eq!(error.rule(), Some("E_RECIPIENT_SET_HANDLE_MISMATCH"));
}

#[test]
fn test_evaluate_file_accepts_only_the_named_non_member() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let (artifact, _signer_ctx) =
        load_file_artifact(&home, BOB_MEMBER_HANDLE, &[ALICE_MEMBER_HANDLE]);
    remove_member(&workspace, BOB_MEMBER_HANDLE).unwrap();
    let verified = artifact.verify(OperationOptions::default()).unwrap();
    let decrypt_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let key_store = LocalKeyStore::open(home.path().join("keys")).unwrap();
    let bob_kid = key_store
        .list_kids(&member_handle(BOB_MEMBER_HANDLE))
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let evaluator =
        TrustPolicyEvaluator::new(CurrentMemberSnapshot::load(&workspace).unwrap(), None);

    let accepted = evaluator
        .evaluate_file(
            &verified,
            &decrypt_ctx,
            FileReadOperation::Decrypt,
            OperationOptions::default(),
            ReadTrustExceptions::none()
                .accepting_non_member(member_handle(BOB_MEMBER_HANDLE), bob_kid),
        )
        .unwrap();
    assert!(matches!(accepted, TrustDecision::Trusted(_)));

    let wrong_kid = Kid::new("0123456789ABCDEFGHJKMNPQRSTVWXYZ").unwrap();
    let error = evaluator
        .evaluate_file(
            &verified,
            &decrypt_ctx,
            FileReadOperation::Decrypt,
            OperationOptions::default(),
            ReadTrustExceptions::none()
                .accepting_non_member(member_handle(BOB_MEMBER_HANDLE), wrong_kid),
        )
        .err()
        .expect("a different kid must remain rejected");
    assert_eq!(error.rule(), Some("E_TRUST_NON_MEMBER"));
}

#[test]
fn test_evaluate_kv_rejects_non_member_exception_for_environment() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let key_store = LocalKeyStore::open(home.path().join("keys")).unwrap();
    let signer_ctx = load_key_context(&home, BOB_MEMBER_HANDLE);
    let decrypt_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let recipients = key_store
        .load_recipient_keys([member_handle(ALICE_MEMBER_HANDLE)])
        .unwrap();
    let artifact = KvEncArtifact::encrypt_entries(
        vec![KvInputEntry::new(
            "SECRET",
            SecretString::new("value".to_string()),
        )],
        &recipients,
        &signer_ctx,
    )
    .unwrap();
    remove_member(&workspace, BOB_MEMBER_HANDLE).unwrap();
    let verified = artifact.verify(OperationOptions::default()).unwrap();
    let bob_kid = key_store
        .list_kids(&member_handle(BOB_MEMBER_HANDLE))
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let evaluator =
        TrustPolicyEvaluator::new(CurrentMemberSnapshot::load(&workspace).unwrap(), None);

    let error = evaluator
        .evaluate_kv(
            &verified,
            &decrypt_ctx,
            KvReadOperation::Environment,
            OperationOptions::default(),
            ReadTrustExceptions::none()
                .accepting_non_member(member_handle(BOB_MEMBER_HANDLE), bob_kid),
        )
        .err()
        .expect("environment reads must reject non-member exceptions");

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
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
            ReadTrustExceptions::none(),
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
            ReadTrustExceptions::none(),
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
            ReadTrustExceptions::none(),
        )
        .expect("evaluate trust");

    let TrustDecision::ReviewRequired(requests) = decision else {
        panic!("unknown current recipient key must require review");
    };
    assert!(requests.iter().any(|request| {
        request.kind() == TrustReviewKind::KnownKey
            && request.subject_handle().map(|handle| handle.as_str()) == Some(BOB_MEMBER_HANDLE)
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
