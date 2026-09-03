// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Read trust-gate tests for operation-bound public artifact facades.
//! Covers current-member authorization, review requests, and trusted reads.

use crate::api::config::LocalStateSession;
use crate::api::file::{FileEncArtifact, FileReadOperation};
use crate::api::key::{KeyContext, KeyContextOptions, Kid, LocalKeyStore};
use crate::api::kv::{KvEncArtifact, KvInputEntry, KvReadOperation};
use crate::api::operation::OperationOptions;
use crate::api::secret::SecretString;
use crate::api::ssh::{SshRawSignature, SshSignatureBackend};
use crate::api::trust::{
    ApprovalConflictHandling, CurrentMemberSnapshot, KnownKeyApprovalEvidence, KnownKeyReview,
    LocalTrustStore, ReadSessionDecision, ReadTrustExceptions, TrustApproval, TrustDecision,
    TrustPolicyEvaluator, TrustReviewKind, WorkspaceReadSession,
};
use crate::feature::trust::recipient_sets::ArtifactRecipientSet;
use crate::feature::trust::signature::sign_trust_store;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::io::workspace::members::load_active_member_files;
use crate::io::workspace::members::test_support::remove_active_member as remove_member;
use crate::model::trust_store::{RecipientHandleHint, TrustStoreProtected};
use crate::model::wire::format::LOCAL_TRUST_V1;
use crate::test_support::storage::keystore::active::set_active_kid;
use crate::test_support::storage::keystore::storage::save_key_pair_atomic;
use crate::test_support::storage::trust::store::save_trust_store;
use crate::test_utils::{
    build_expiring_soon_timestamp, build_test_private_key, keygen_test, member_handle,
    save_active_public_key_to_workspace, setup_member_key_context,
    setup_test_workspace_from_fixtures, update_active_private_key_expires_at, ALICE_MEMBER_HANDLE,
    BOB_MEMBER_HANDLE, CAROL_MEMBER_HANDLE,
};

struct HomeBoundSshBackend {
    inner: crate::test_utils::ed25519_backend::Ed25519DirectBackend,
}

impl SshSignatureBackend for HomeBoundSshBackend {
    fn sign_sshsig(
        &self,
        namespace: &str,
        ssh_pubkey: &str,
        message: &[u8],
    ) -> crate::Result<SshRawSignature> {
        let signature = crate::io::ssh::backend::SignatureBackend::sign_sshsig(
            &self.inner,
            namespace,
            ssh_pubkey,
            message,
        )?;
        Ok(SshRawSignature::new(*signature.as_bytes()))
    }
}

fn add_generated_member(
    home: &tempfile::TempDir,
    workspace: &std::path::Path,
    member_handle: &str,
) {
    let ssh_private_key = home.path().join(".ssh/test_ed25519");
    let ssh_public_key = std::fs::read_to_string(home.path().join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let (private, public) = keygen_test(member_handle, &ssh_private_key, &ssh_public_key).unwrap();
    let private = build_test_private_key(
        &private,
        &public.protected.subject_handle,
        &public.protected.kid,
        &ssh_private_key,
        &ssh_public_key,
    )
    .unwrap();
    let keys = home.path().join("keys");
    save_key_pair_atomic(
        &keys,
        member_handle,
        &public.protected.kid,
        &private,
        &public,
    )
    .unwrap();
    set_active_kid(member_handle, &public.protected.kid, &keys).unwrap();
    std::fs::write(
        workspace
            .join("members/active")
            .join(format!("{member_handle}.json")),
        serde_json::to_string_pretty(&public).unwrap(),
    )
    .unwrap();
}

fn load_key_context(home: &tempfile::TempDir, member_handle: &str) -> KeyContext {
    KeyContext::from_inner(setup_member_key_context(home, member_handle, None))
}

fn load_home_bound_key_context(home: &tempfile::TempDir, member_handle_value: &str) -> KeyContext {
    let local_state = LocalStateSession::open(home.path()).unwrap();
    let member = member_handle(member_handle_value);
    let key_store = local_state.require_key_store(&member).unwrap();
    let ssh_private_key = home.path().join(".ssh/test_ed25519");
    let ssh_public_key = std::fs::read_to_string(home.path().join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let backend = HomeBoundSshBackend {
        inner: crate::test_utils::ed25519_backend::Ed25519DirectBackend::new(&ssh_private_key)
            .unwrap(),
    };
    key_store
        .load_key_context(KeyContextOptions::new(
            member,
            Box::new(backend),
            ssh_public_key,
        ))
        .unwrap()
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

fn open_read_session<'a>(
    home: &tempfile::TempDir,
    workspace: &std::path::Path,
    key_ctx: &'a KeyContext,
) -> WorkspaceReadSession<'a> {
    let local_state = LocalStateSession::open(home.path()).unwrap();
    WorkspaceReadSession::open_with_local_state(
        workspace,
        Some(&local_state),
        key_ctx,
        OperationOptions::default(),
    )
    .expect("open workspace read session")
}

#[test]
fn test_workspace_read_session_requires_an_existing_secrets_directory() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    std::fs::remove_dir(workspace.join("secrets")).expect("remove secrets directory");
    let decrypt_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);

    let local_state = LocalStateSession::open(home.path()).unwrap();
    let error = match WorkspaceReadSession::open_with_local_state(
        &workspace,
        Some(&local_state),
        &decrypt_ctx,
        OperationOptions::default(),
    ) {
        Ok(_) => panic!("a read session must not create a missing secrets directory"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), crate::ErrorKind::NotFound);
    assert!(!workspace.join("secrets").exists());
}

#[test]
fn test_workspace_read_session_rejects_a_different_local_state_home() {
    let (key_home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let other_home = crate::test_utils::local_state_temp_dir();
    let key_ctx = load_home_bound_key_context(&key_home, ALICE_MEMBER_HANDLE);
    let local_state = LocalStateSession::open(other_home.path()).unwrap();

    let error = match WorkspaceReadSession::open_with_local_state(
        &workspace,
        Some(&local_state),
        &key_ctx,
        OperationOptions::default(),
    ) {
        Ok(_) => panic!("a key from another local-state home must be rejected"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert!(error.to_string().contains("different local-state home"));
}

#[cfg(unix)]
#[test]
fn test_workspace_read_session_keeps_the_matching_local_state_capability_after_repointing() {
    use std::os::unix::fs::symlink;

    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let links = crate::test_utils::local_state_temp_dir();
    let alias = links.path().join("home");
    let replacement = links.path().join("replacement");
    crate::test_utils::create_local_state_dir(&replacement);
    symlink(home.path(), &alias).unwrap();
    let key_ctx = load_home_bound_key_context(&home, ALICE_MEMBER_HANDLE);
    let local_state = LocalStateSession::open(&alias).unwrap();
    let session = WorkspaceReadSession::open_with_local_state(
        &workspace,
        Some(&local_state),
        &key_ctx,
        OperationOptions::default(),
    )
    .expect("directory identity, rather than path spelling, must be compared");
    std::fs::remove_file(&alias).unwrap();
    symlink(&replacement, &alias).unwrap();

    session.apply_approvals(Vec::new()).unwrap();

    assert!(home.path().join("trust").is_dir());
    assert!(!replacement.join("trust").exists());
}

fn save_file_artifact(
    workspace: &std::path::Path,
    name: &str,
    artifact: &FileEncArtifact,
) -> std::path::PathBuf {
    let path = workspace.join(name);
    artifact.save(&path).unwrap();
    path
}

fn save_kv_artifact(workspace: &std::path::Path, name: &str, artifact: &KvEncArtifact) {
    artifact.save(workspace.join("secrets").join(name)).unwrap();
}

#[test]
fn test_workspace_read_session_resumes_non_member_for_exact_file_artifact() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let (artifact, _signer_ctx) =
        load_file_artifact(&home, BOB_MEMBER_HANDLE, &[ALICE_MEMBER_HANDLE]);
    let artifact_path = save_file_artifact(&workspace, "reviewed.json", &artifact);
    remove_member(&workspace, BOB_MEMBER_HANDLE).expect("remove current signer");
    let decrypt_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let session = open_read_session(&home, &workspace, &decrypt_ctx);
    let target = session.open_file_read_target(&artifact_path).unwrap();

    let decision = session
        .begin_file_read(&target, FileReadOperation::Decrypt, true)
        .expect("begin file read");
    let ReadSessionDecision::ReviewRequired(mut review) = decision else {
        panic!("non-member signer must require opaque review");
    };
    assert_eq!(
        review
            .non_member_signer()
            .expect("non-member review")
            .candidate()
            .subject_handle()
            .as_str(),
        BOB_MEMBER_HANDLE
    );
    let acceptance = review
        .accept_non_member()
        .expect("accept the review-bound signer");
    let second_acceptance = match review.accept_non_member() {
        Ok(_) => panic!("one review must mint at most one acceptance"),
        Err(error) => error,
    };
    assert_eq!(second_acceptance.kind(), crate::ErrorKind::InvalidOperation);

    let resumed = session
        .resume_file_read(review, Some(acceptance))
        .expect("resume reviewed file read");
    let ReadSessionDecision::Authorized(authorized) = resumed else {
        panic!("the exact reviewed artifact must be authorized");
    };
    assert_eq!(
        authorized
            .into_value()
            .decrypt_bytes()
            .unwrap()
            .expose_secret(),
        b"secret"
    );
}

#[test]
fn test_workspace_read_session_retains_reader_bytes_across_authorization() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let (artifact, _signer_ctx) =
        load_file_artifact(&home, ALICE_MEMBER_HANDLE, &[ALICE_MEMBER_HANDLE]);
    let decrypt_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let session = open_read_session(&home, &workspace, &decrypt_ctx);
    let target = session
        .capture_file_read_target(artifact.as_str().as_bytes(), "stdin")
        .unwrap();

    let ReadSessionDecision::Authorized(authorized) = session
        .begin_file_read(&target, FileReadOperation::Decrypt, false)
        .unwrap()
    else {
        panic!("self-signed captured input must be authorized");
    };

    assert_eq!(
        authorized
            .into_value()
            .decrypt_bytes()
            .unwrap()
            .expose_secret(),
        b"secret"
    );
}

#[test]
fn test_workspace_read_session_marks_current_signer_key_review_first() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let (artifact, _signer_ctx) =
        load_file_artifact(&home, BOB_MEMBER_HANDLE, &[ALICE_MEMBER_HANDLE]);
    let artifact_path = save_file_artifact(&workspace, "reviewed.json", &artifact);
    let decrypt_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let session = open_read_session(&home, &workspace, &decrypt_ctx);
    let target = session.open_file_read_target(&artifact_path).unwrap();

    let ReadSessionDecision::ReviewRequired(review) = session
        .begin_file_read(&target, FileReadOperation::Decrypt, false)
        .unwrap()
    else {
        panic!("unknown current signer key must require review");
    };

    assert!(review.first_request_is_signer());
    assert_eq!(review.requests().len(), 1);
}

#[test]
fn test_workspace_read_session_skips_current_file_signer_key_review() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let (artifact, _signer_ctx) =
        load_file_artifact(&home, BOB_MEMBER_HANDLE, &[ALICE_MEMBER_HANDLE]);
    let artifact_path = save_file_artifact(&workspace, "reviewed.json", &artifact);
    let decrypt_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let session = open_read_session(&home, &workspace, &decrypt_ctx)
        .with_known_key_review(KnownKeyReview::Skipped);
    let target = session.open_file_read_target(&artifact_path).unwrap();

    let ReadSessionDecision::Authorized(authorized) = session
        .begin_file_read(&target, FileReadOperation::Decrypt, false)
        .unwrap()
    else {
        panic!("skipped known-key review must authorize a current signer");
    };

    assert_eq!(
        authorized
            .into_value()
            .decrypt_bytes()
            .unwrap()
            .expose_secret(),
        b"secret"
    );
}

#[test]
fn test_workspace_read_session_skips_current_kv_signer_key_review() {
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
    save_kv_artifact(&workspace, "reviewed.env", &artifact);
    let required_session = open_read_session(&home, &workspace, &decrypt_ctx);

    let ReadSessionDecision::ReviewRequired(review) = required_session
        .begin_kv_read("reviewed.env", KvReadOperation::Entries, false)
        .unwrap()
    else {
        panic!("known-key review must remain required by default");
    };
    assert!(review.first_request_is_signer());

    let skipped_session = open_read_session(&home, &workspace, &decrypt_ctx)
        .with_known_key_review(KnownKeyReview::Skipped);
    let ReadSessionDecision::Authorized(authorized) = skipped_session
        .begin_kv_read("reviewed.env", KvReadOperation::Entries, false)
        .unwrap()
    else {
        panic!("skipped known-key review must authorize a current KV signer");
    };
    let result = authorized.into_value().get_result().unwrap();
    assert_eq!(result.values()["SECRET"].expose_secret(), "value");
}

#[test]
fn test_workspace_read_session_coalesces_same_file_signer_and_decryption_key_warning() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let expires_at = build_expiring_soon_timestamp(15);
    update_active_private_key_expires_at(home.path(), ALICE_MEMBER_HANDLE, &expires_at);
    save_active_public_key_to_workspace(home.path(), &workspace, ALICE_MEMBER_HANDLE).unwrap();
    let (artifact, decrypt_ctx) =
        load_file_artifact(&home, ALICE_MEMBER_HANDLE, &[ALICE_MEMBER_HANDLE]);
    let artifact_path = save_file_artifact(&workspace, "expiring.json", &artifact);
    let session = open_read_session(&home, &workspace, &decrypt_ctx);
    let target = session.open_file_read_target(&artifact_path).unwrap();

    let ReadSessionDecision::Authorized(authorized) = session
        .begin_file_read(&target, FileReadOperation::Decrypt, false)
        .unwrap()
    else {
        panic!("self-signed file must be authorized");
    };
    let warnings = authorized.value().warnings();

    assert_eq!(
        warnings
            .iter()
            .filter(|warning| warning.contains(&expires_at))
            .count(),
        1,
        "{warnings:?}"
    );
    assert!(warnings
        .iter()
        .any(|warning| warning.starts_with("Local key expires in ")));
}

#[test]
fn test_workspace_read_session_retains_distinct_kv_signer_and_decryption_key_warnings() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let expires_at = build_expiring_soon_timestamp(15);
    for member_handle in [ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE] {
        update_active_private_key_expires_at(home.path(), member_handle, &expires_at);
        save_active_public_key_to_workspace(home.path(), &workspace, member_handle).unwrap();
    }
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
    save_kv_artifact(&workspace, "expiring.env", &artifact);
    let session = open_read_session(&home, &workspace, &decrypt_ctx)
        .with_known_key_review(KnownKeyReview::Skipped);

    let ReadSessionDecision::Authorized(authorized) = session
        .begin_kv_read("expiring.env", KvReadOperation::Entries, false)
        .unwrap()
    else {
        panic!("skipped known-key review must authorize the current signer");
    };
    let warnings = authorized.value().warnings();

    assert!(warnings
        .iter()
        .any(|warning| warning.starts_with("Artifact signing key expires in ")));
    assert!(warnings
        .iter()
        .any(|warning| warning.starts_with("Local key expires in ")));
}

#[test]
fn test_workspace_read_session_reloads_trust_store_after_key_approval() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let (artifact, _signer_ctx) =
        load_file_artifact(&home, BOB_MEMBER_HANDLE, &[ALICE_MEMBER_HANDLE]);
    let artifact_path = save_file_artifact(&workspace, "reviewed.json", &artifact);
    let decrypt_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let session = open_read_session(&home, &workspace, &decrypt_ctx);
    let target = session.open_file_read_target(&artifact_path).unwrap();

    let ReadSessionDecision::ReviewRequired(review) = session
        .begin_file_read(&target, FileReadOperation::Decrypt, false)
        .unwrap()
    else {
        panic!("unknown current signer key must require review");
    };
    let candidate = review.requests()[0]
        .known_key_candidate()
        .expect("signer review candidate");
    let approval = TrustApproval::known_key(candidate, KnownKeyApprovalEvidence::none()).unwrap();
    session.apply_approvals(vec![approval]).unwrap();

    let ReadSessionDecision::Authorized(authorized) =
        session.resume_file_read(review, None).unwrap()
    else {
        panic!("saved signer approval must be reloaded before authorization");
    };
    assert_eq!(
        authorized
            .into_value()
            .decrypt_bytes()
            .unwrap()
            .expose_secret(),
        b"secret"
    );
}

#[test]
fn test_workspace_read_session_reloads_members_before_resume() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let (artifact, _signer_ctx) =
        load_file_artifact(&home, BOB_MEMBER_HANDLE, &[ALICE_MEMBER_HANDLE]);
    let artifact_path = save_file_artifact(&workspace, "reviewed.json", &artifact);
    let decrypt_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let session = open_read_session(&home, &workspace, &decrypt_ctx);
    let target = session.open_file_read_target(&artifact_path).unwrap();

    let ReadSessionDecision::ReviewRequired(review) = session
        .begin_file_read(&target, FileReadOperation::Decrypt, false)
        .unwrap()
    else {
        panic!("unknown current signer key must require review");
    };
    remove_member(&workspace, BOB_MEMBER_HANDLE).unwrap();

    let error = match session.resume_file_read(review, None) {
        Ok(_) => panic!("retired signer must not receive an authorized capability"),
        Err(error) => error,
    };
    assert_eq!(error.rule(), Some("E_TRUST_NON_MEMBER"));
}

#[test]
fn test_workspace_read_session_carries_acceptance_into_recipient_only_review() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    add_generated_member(&home, &workspace, CAROL_MEMBER_HANDLE);
    let (artifact, _signer_ctx) = load_file_artifact(
        &home,
        BOB_MEMBER_HANDLE,
        &[ALICE_MEMBER_HANDLE, CAROL_MEMBER_HANDLE],
    );
    let artifact_path = save_file_artifact(&workspace, "reviewed.json", &artifact);
    remove_member(&workspace, BOB_MEMBER_HANDLE).unwrap();
    let decrypt_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let session = open_read_session(&home, &workspace, &decrypt_ctx);
    let target = session.open_file_read_target(&artifact_path).unwrap();

    let ReadSessionDecision::ReviewRequired(mut signer_review) = session
        .begin_file_read(&target, FileReadOperation::Decrypt, true)
        .unwrap()
    else {
        panic!("signer and recipient must require review");
    };
    assert!(signer_review.non_member_signer().is_some());
    assert!(signer_review.requests().is_empty());
    let acceptance = signer_review.accept_non_member().unwrap();

    let ReadSessionDecision::ReviewRequired(recipient_review) = session
        .resume_file_read(signer_review, Some(acceptance))
        .unwrap()
    else {
        panic!("recipient approval must remain required");
    };
    assert!(recipient_review.non_member_signer().is_none());
    assert!(!recipient_review.first_request_is_signer());
    assert!(!recipient_review.requests().is_empty());

    let ReadSessionDecision::ReviewRequired(still_recipient_review) =
        session.resume_file_read(recipient_review, None).unwrap()
    else {
        panic!("opaque review must carry the accepted signer into the next resume");
    };
    assert!(still_recipient_review.non_member_signer().is_none());
    assert!(!still_recipient_review.requests().is_empty());
}

#[test]
fn test_workspace_read_session_rejects_acceptance_for_changed_artifact() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let (reviewed_artifact, _signer_ctx) =
        load_file_artifact(&home, BOB_MEMBER_HANDLE, &[ALICE_MEMBER_HANDLE]);
    let (replacement_artifact, _signer_ctx) =
        load_file_artifact(&home, BOB_MEMBER_HANDLE, &[ALICE_MEMBER_HANDLE]);
    let artifact_path = save_file_artifact(&workspace, "reviewed.json", &reviewed_artifact);
    remove_member(&workspace, BOB_MEMBER_HANDLE).expect("remove current signer");
    let decrypt_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let session = open_read_session(&home, &workspace, &decrypt_ctx);
    let target = session.open_file_read_target(&artifact_path).unwrap();

    let ReadSessionDecision::ReviewRequired(mut review) = session
        .begin_file_read(&target, FileReadOperation::Decrypt, true)
        .unwrap()
    else {
        panic!("non-member signer must require review");
    };
    let acceptance = review.accept_non_member().unwrap();
    std::fs::write(&artifact_path, replacement_artifact.as_str()).unwrap();
    let error = match session.resume_file_read(review, Some(acceptance)) {
        Ok(_) => panic!("acceptance must be bound to the reviewed artifact"),
        Err(error) => error,
    };

    assert_eq!(error.rule(), Some("E_TRUST_TARGET_CHANGED"));
}

#[test]
fn test_workspace_read_session_rejects_acceptance_for_another_kv_operation() {
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
    save_kv_artifact(&workspace, "reviewed.env", &artifact);
    remove_member(&workspace, BOB_MEMBER_HANDLE).unwrap();
    let session = open_read_session(&home, &workspace, &decrypt_ctx);

    let ReadSessionDecision::ReviewRequired(mut list_review) = session
        .begin_kv_read("reviewed.env", KvReadOperation::List, true)
        .unwrap()
    else {
        panic!("list must require non-member review");
    };
    let list_acceptance = list_review.accept_non_member().unwrap();
    let ReadSessionDecision::ReviewRequired(entry_review) = session
        .begin_kv_read(
            "reviewed.env",
            KvReadOperation::Entry("SECRET".to_string()),
            true,
        )
        .unwrap()
    else {
        panic!("entry must require its own non-member review");
    };

    let error = match session.resume_kv_read(entry_review, Some(list_acceptance)) {
        Ok(_) => panic!("acceptance must be bound to one operation and review"),
        Err(error) => error,
    };
    assert_eq!(error.rule(), Some("E_TRUST_TARGET_CHANGED"));
}

#[test]
fn test_workspace_read_session_rejects_changed_kv_content_on_resume() {
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let key_store = LocalKeyStore::open(home.path().join("keys")).unwrap();
    let signer_ctx = load_key_context(&home, BOB_MEMBER_HANDLE);
    let decrypt_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let recipients = key_store
        .load_recipient_keys([member_handle(ALICE_MEMBER_HANDLE)])
        .unwrap();
    let artifact = |value: &str| {
        KvEncArtifact::encrypt_entries(
            vec![KvInputEntry::new(
                "SECRET",
                SecretString::new(value.to_string()),
            )],
            &recipients,
            &signer_ctx,
        )
        .unwrap()
    };
    save_kv_artifact(&workspace, "reviewed.env", &artifact("reviewed"));
    remove_member(&workspace, BOB_MEMBER_HANDLE).unwrap();
    let session = open_read_session(&home, &workspace, &decrypt_ctx);

    let ReadSessionDecision::ReviewRequired(mut review) = session
        .begin_kv_read("reviewed.env", KvReadOperation::Entries, true)
        .unwrap()
    else {
        panic!("non-member signer must require review");
    };
    let acceptance = review.accept_non_member().unwrap();
    save_kv_artifact(&workspace, "reviewed.env", &artifact("replacement"));

    let error = match session.resume_kv_read(review, Some(acceptance)) {
        Ok(_) => panic!("changed KV bytes must invalidate the acceptance"),
        Err(error) => error,
    };
    assert_eq!(error.rule(), Some("E_TRUST_TARGET_CHANGED"));
}

#[test]
fn test_workspace_read_session_environment_never_offers_non_member_review() {
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
    save_kv_artifact(&workspace, "reviewed.env", &artifact);
    remove_member(&workspace, BOB_MEMBER_HANDLE).unwrap();
    let session = open_read_session(&home, &workspace, &decrypt_ctx);

    let error = match session.begin_kv_read("reviewed.env", KvReadOperation::Environment, true) {
        Ok(_) => panic!("environment reads must fail instead of offering acceptance"),
        Err(error) => error,
    };
    assert_eq!(error.rule(), Some("E_TRUST_NON_MEMBER"));
}

#[test]
fn test_workspace_read_session_get_result_uses_one_authorized_capability() {
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let key_store = LocalKeyStore::open(home.path().join("keys")).unwrap();
    let key_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE);
    let recipients = key_store
        .load_recipient_keys([member_handle(ALICE_MEMBER_HANDLE)])
        .unwrap();
    let artifact = KvEncArtifact::encrypt_entries(
        vec![KvInputEntry::new(
            "SECRET",
            SecretString::new("value".to_string()),
        )],
        &recipients,
        &key_ctx,
    )
    .unwrap();
    save_kv_artifact(&workspace, "reviewed.env", &artifact);
    let session = open_read_session(&home, &workspace, &key_ctx);

    let decision = session
        .begin_kv_read("reviewed.env", KvReadOperation::Entries, false)
        .unwrap();
    let ReadSessionDecision::Authorized(authorized) = decision else {
        panic!("self read must be authorized");
    };
    let result = authorized.into_value().get_result().unwrap();

    assert_eq!(result.values()["SECRET"].expose_secret(), "value");
    assert_eq!(result.disclosed_entries().len(), 1);
    assert_eq!(result.disclosed_entries()[0].key(), "SECRET");
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
