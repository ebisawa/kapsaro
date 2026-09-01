// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use kapsaro_core::api::diagnostics::{
    DiagnosticBatch, DiagnosticCode, DiagnosticCompleteness, DiagnosticTruncation,
    LocalStateDiagnostic,
};
use kapsaro_core::api::file::{
    FileEncArtifact, FileReadOperation, TrustedFileEncArtifact, VerifiedFileEncArtifact,
};
use kapsaro_core::api::key::{
    KeyContext, KeyContextOptions, Kid, LocalKeyStore, MemberHandle, RecipientKeys,
};
use kapsaro_core::api::kv::{
    AuthorizedKvMutation, KvDisclosedEntry, KvEncArtifact, KvInputEntry, KvMutationOperation,
    KvReadOperation, TrustedKvEncArtifact, VerifiedKvEncArtifact,
};
use kapsaro_core::api::online::{
    GitHubAccount, GitHubOnlineVerifier, OnlineVerificationStatus, VerifiedGitHubEvidence,
};
use kapsaro_core::api::operation::OperationOptions;
use kapsaro_core::api::secret::{SecretBytes, SecretString};
use kapsaro_core::api::ssh::{SshRawSignature, SshSignatureBackend};
use kapsaro_core::api::trust::{
    ApprovalConflictHandling, CurrentMemberSnapshot, KnownKeyApprovalEvidence, KnownKeyReview,
    KnownKeyReviewCandidate, LocalTrustStore, ReadTrustExceptions, RecipientSetSubject,
    TrustApproval, TrustApprovalOutcome, TrustDecision, TrustPolicyEvaluator,
    TrustRecipientHandleHint, TrustReviewKind, TrustReviewRequest, VerifiedLocalTrustStore,
    VerifiedLocalTrustStoreLoadResult,
};
use kapsaro_core::{Error, ErrorKind, Result};
use std::error::Error as StdError;
use zeroize::Zeroizing;

/// Temporary directory usable as a local state root.
///
/// Local state refuses a path any other user can write, and `tempdir` applies
/// the process umask, so a bare temporary directory is group-writable wherever
/// the developer runs with a 002 umask.
fn local_state_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restrict local state tempdir");
    }
    dir
}

struct StubSshBackend;

impl SshSignatureBackend for StubSshBackend {
    fn sign_sshsig(
        &self,
        _namespace: &str,
        _ssh_pubkey: &str,
        _message: &[u8],
    ) -> Result<SshRawSignature> {
        Ok(SshRawSignature::new([0u8; 64]))
    }
}

#[test]
fn api_exposes_use_case_modules() {
    let temp = local_state_tempdir();
    let member_handle = MemberHandle::try_from("alice@example.com").expect("valid member handle");
    let key_store = LocalKeyStore::create(temp.path().join("keys")).expect("create keystore");
    let trust_store = LocalTrustStore::open(temp.path(), member_handle).expect("open trust store");
    let _signature = kapsaro_core::api::ssh::SshRawSignature::new([3u8; 64]);
    let _secret = kapsaro_core::api::secret::SecretString::new("secret".to_string());
    let _bytes = kapsaro_core::api::secret::SecretBytes::new(vec![1, 2, 3]);
    let _options = kapsaro_core::api::operation::OperationOptions::default();
    let _online = kapsaro_core::api::online::GitHubOnlineVerifier::new();
    let _warnings = kapsaro_core::api::diagnostics::take_local_state_warnings();

    assert_eq!(key_store.root(), temp.path().join("keys").as_path());
    assert_eq!(
        trust_store.path(),
        temp.path().join("trust/alice@example.com.json")
    );
}

#[test]
fn test_local_state_facade_debug_names_only_the_facade() {
    let temp = local_state_tempdir();
    let member_handle = MemberHandle::try_from("alice@example.com").expect("valid member handle");
    let key_store = LocalKeyStore::create(temp.path().join("keys")).expect("create keystore");
    let trust_store = LocalTrustStore::open(temp.path(), member_handle).expect("open trust store");

    assert_eq!(format!("{key_store:?}"), "LocalKeyStore { .. }");
    assert_eq!(format!("{trust_store:?}"), "LocalTrustStore { .. }");
}

#[test]
fn key_context_options_group_runtime_inputs() {
    let member_handle = MemberHandle::try_from("alice@example.com").expect("valid member handle");
    let _options = KeyContextOptions::new(
        member_handle,
        Box::new(StubSshBackend),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA".to_string(),
    )
    .with_kid(Kid::try_from("0123456789ABCDEFGHJKMNPQRSTVWXYZ").expect("valid kid"))
    .with_workspace_path(std::path::PathBuf::from("/tmp/workspace"));

    let _load_key_context = LocalKeyStore::load_key_context;
}

#[test]
fn test_member_handle_deserialization_path_like_value_error() {
    for value in ["", "../outside", "/tmp/outside", "alice/bob", r"alice\bob"] {
        let serialized = serde_json::to_string(value).expect("serialize test value");
        let error = serde_json::from_str::<MemberHandle>(&serialized)
            .expect_err("path-like member handle must be rejected");
        assert!(error.to_string().contains("member_handle"));
    }
}

#[test]
fn trust_store_exposes_verified_opaque_load_names() {
    let _open: fn(std::path::PathBuf, MemberHandle) -> Result<LocalTrustStore> =
        LocalTrustStore::open;
    let _create: fn(std::path::PathBuf, MemberHandle) -> Result<LocalTrustStore> =
        LocalTrustStore::create;
    let _load_verified = LocalTrustStore::load_verified;

    assert!(std::any::type_name::<TrustApproval>().contains("TrustApproval"));
}

#[test]
fn missing_trust_store_loads_as_none() {
    let temp = local_state_tempdir();
    let member_handle = MemberHandle::try_from("alice@example.com").expect("valid member handle");
    let key_store = LocalKeyStore::create(temp.path().join("keys")).expect("create keystore");
    let trust_store = LocalTrustStore::open(temp.path(), member_handle).expect("open trust store");

    assert!(trust_store
        .load_verified(&key_store)
        .expect("load missing trust store")
        .is_none());
}

#[test]
fn canonical_api_exposes_facade_helper_types() {
    let entry = KvInputEntry::new(
        "DATABASE_URL",
        SecretString::new("postgres://example".to_string()),
    );
    let secret = SecretString::new("secret".to_string());
    let bytes = SecretBytes::new(vec![1, 2, 3]);
    let signature = SshRawSignature::new([7u8; 64]);

    assert_eq!(entry.key(), "DATABASE_URL");
    assert_eq!(secret.expose_secret(), "secret");
    assert_eq!(bytes.expose_secret(), &[1, 2, 3]);
    assert_eq!(signature.as_bytes(), &[7u8; 64]);
    assert!(std::any::type_name::<&dyn SshSignatureBackend>().contains("SshSignatureBackend"));
    assert!(std::any::type_name::<KeyContextOptions>().contains("KeyContextOptions"));
    assert!(std::any::type_name::<RecipientSetSubject>().contains("RecipientSetSubject"));
    assert!(std::any::type_name::<VerifiedFileEncArtifact>().contains("VerifiedFileEncArtifact"));
    assert!(std::any::type_name::<VerifiedKvEncArtifact>().contains("VerifiedKvEncArtifact"));
    assert!(std::any::type_name::<VerifiedLocalTrustStore>().contains("VerifiedLocalTrustStore"));
    assert!(std::any::type_name::<LocalTrustStore>().contains("LocalTrustStore"));
    assert!(
        std::any::type_name::<TrustDecision<TrustedFileEncArtifact<'static>>>()
            .contains("TrustDecision")
    );
    assert!(std::any::type_name::<TrustPolicyEvaluator>().contains("TrustPolicyEvaluator"));
    assert!(std::any::type_name::<GitHubAccount>().contains("GitHubAccount"));
    assert!(std::any::type_name::<VerifiedGitHubEvidence>().contains("VerifiedGitHubEvidence"));
    assert_eq!(
        OnlineVerificationStatus::Verified,
        OnlineVerificationStatus::Verified
    );
    assert!(OnlineVerificationStatus::Verified.is_verified());
}

#[test]
fn secret_facade_debug_redacts_and_plain_output_is_explicit() {
    let secret = SecretString::new("do-not-log".to_string());
    let bytes = SecretBytes::new(b"do-not-log".to_vec());

    assert_eq!(
        format!("{secret:?}"),
        "SecretString { value: \"[REDACTED]\", len: 10 }"
    );
    assert_eq!(
        format!("{bytes:?}"),
        "SecretBytes { bytes: \"[REDACTED]\", len: 10 }"
    );
    assert_eq!(
        SecretString::new("plain at boundary".to_string()).into_plain_string_for_output(),
        "plain at boundary"
    );
    assert_eq!(
        SecretString::from_zeroizing(Zeroizing::new("zeroizing input".to_string())).expose_secret(),
        "zeroizing input"
    );
}

#[test]
fn error_exposes_stable_kind_for_embedding_apps() {
    let error = Error::build_invalid_argument_error("member handle mismatch");

    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    assert_eq!(error.format_user_message(), "member handle mismatch");
}

#[test]
fn kv_artifact_exposes_entry_named_operations() {
    assert!(std::any::type_name::<
        fn(Vec<KvInputEntry>, &RecipientKeys, &KeyContext) -> Result<KvEncArtifact>,
    >()
    .contains("fn"));

    let _encrypt_entries = KvEncArtifact::encrypt_entries;
    let _list_entry_keys = TrustedKvEncArtifact::list_entry_keys;
    let _decrypt_entry = TrustedKvEncArtifact::decrypt_entry;
    let _decrypt_entries = TrustedKvEncArtifact::decrypt_entries;
    let _decrypt_environment = TrustedKvEncArtifact::decrypt_environment;
    let _set_entries = AuthorizedKvMutation::set_entries;
    let _unset_entry = AuthorizedKvMutation::unset_entry;
}

#[test]
fn artifact_facades_expose_verified_operations() {
    let _verify_file = FileEncArtifact::verify;
    let _verify_kv = KvEncArtifact::verify;
    let _decrypt_file = TrustedFileEncArtifact::decrypt_bytes;
    let _decrypt_kv_entry = TrustedKvEncArtifact::decrypt_entry;
    let _decrypt_kv_entries = TrustedKvEncArtifact::decrypt_entries;
    let _set_kv_entries = AuthorizedKvMutation::set_entries;
    let _unset_kv_entry = AuthorizedKvMutation::unset_entry;

    assert!(std::any::type_name::<VerifiedFileEncArtifact>().contains("VerifiedFileEncArtifact"));
    assert!(std::any::type_name::<VerifiedKvEncArtifact>().contains("VerifiedKvEncArtifact"));
}

#[test]
fn trust_evaluator_exposes_operation_bound_decisions() {
    let _load_snapshot = CurrentMemberSnapshot::load;
    let _evaluate_file = TrustPolicyEvaluator::evaluate_file;
    let _evaluate_kv = TrustPolicyEvaluator::evaluate_kv;
    let _evaluate_kv_mutation = TrustPolicyEvaluator::evaluate_kv_mutation;
    let _file_operation = FileReadOperation::Decrypt;
    let _kv_operation = KvReadOperation::Entry("DATABASE_URL".to_string());
    let _kv_mutation = KvMutationOperation::Set;
    let _review_kind = TrustReviewKind::KnownKey;
}

#[test]
#[cfg(not(feature = "online"))]
fn online_facade_fails_closed_without_online_feature() {
    use kapsaro_core::api::online::GitHubOnlineVerifier;

    let verifier = GitHubOnlineVerifier::new();
    let error = verifier
        .resolve_account_by_login("alice")
        .expect_err("online facade must fail without online feature");

    assert_eq!(error.kind(), ErrorKind::Config);
}

#[test]
fn test_file_artifact_io_methods_pinned() {
    // Pin parse/load/save/encrypt_bytes/as_str method shapes on FileEncArtifact.
    let _parse: fn(String) -> Result<FileEncArtifact> = FileEncArtifact::parse;
    let _load: fn(&std::path::Path) -> Result<FileEncArtifact> = |p| FileEncArtifact::load(p);
    let _load_reader: fn(std::io::Cursor<Vec<u8>>, String) -> Result<FileEncArtifact> =
        FileEncArtifact::load_reader;
    let _save_fn: fn(&FileEncArtifact, &std::path::Path) -> Result<()> = |a, p| a.save(p);
    let _as_str_fn: fn(&FileEncArtifact) -> &str = FileEncArtifact::as_str;
    let _encrypt_bytes: fn(&[u8], &RecipientKeys, &KeyContext) -> Result<FileEncArtifact> =
        FileEncArtifact::encrypt_bytes;
    // Pin recipient_set_subject on VerifiedFileEncArtifact.
    let _rss: fn(&VerifiedFileEncArtifact) -> Result<RecipientSetSubject> =
        VerifiedFileEncArtifact::recipient_set_subject;
}

#[test]
fn test_kv_artifact_io_methods_pinned() {
    // Pin parse/load/save/as_str on KvEncArtifact.
    let _parse: fn(String) -> Result<KvEncArtifact> = KvEncArtifact::parse;
    let _load: fn(&std::path::Path) -> Result<KvEncArtifact> = |p| KvEncArtifact::load(p);
    let _load_reader: fn(std::io::Cursor<Vec<u8>>, String) -> Result<KvEncArtifact> =
        KvEncArtifact::load_reader;
    let _save_fn: fn(&KvEncArtifact, &std::path::Path) -> Result<()> = |a, p| a.save(p);
    let _as_str_fn: fn(&KvEncArtifact) -> &str = KvEncArtifact::as_str;
    // Pin recipient_set_subject on VerifiedKvEncArtifact.
    let _rss: fn(&VerifiedKvEncArtifact) -> Result<RecipientSetSubject> =
        VerifiedKvEncArtifact::recipient_set_subject;
    // Pin KvDisclosedEntry type and its accessor method shapes.
    assert!(std::any::type_name::<KvDisclosedEntry>().contains("KvDisclosedEntry"));
    let _key_fn: fn(&KvDisclosedEntry) -> &str = KvDisclosedEntry::key;
    let _disclosed_fn: fn(&KvDisclosedEntry) -> bool = KvDisclosedEntry::disclosed;
}

#[test]
fn test_local_key_store_methods_pinned() {
    // Pin construction and member-handle-bound method shapes.
    let _open: fn(std::path::PathBuf) -> Result<LocalKeyStore> = LocalKeyStore::open;
    let _create: fn(std::path::PathBuf) -> Result<LocalKeyStore> = LocalKeyStore::create;
    let _list_members: fn(&LocalKeyStore) -> Result<Vec<MemberHandle>> =
        LocalKeyStore::list_members;
    let _list_kids: fn(&LocalKeyStore, &MemberHandle) -> Result<Vec<Kid>> =
        LocalKeyStore::list_kids;
    let _load_active_kid: fn(&LocalKeyStore, &MemberHandle) -> Result<Option<Kid>> =
        LocalKeyStore::load_active_kid;
    let _set_active_kid: fn(&LocalKeyStore, &MemberHandle, &Kid) -> Result<()> =
        LocalKeyStore::set_active_kid;
    // load_recipient_keys is generic; call the monomorphised version via a concrete iterator.
    let temp = local_state_tempdir();
    let ks = LocalKeyStore::create(temp.path().join("keys")).expect("create keystore");
    let _ = ks.load_recipient_keys(std::iter::empty::<MemberHandle>());
}

#[test]
fn test_key_context_public_accessors_pinned() {
    // Pin member_handle/kid/expires_at method shapes on KeyContext.
    let _member_handle: fn(&KeyContext) -> &MemberHandle = KeyContext::member_handle;
    let _kid: fn(&KeyContext) -> &Kid = KeyContext::kid;
    let _expires_at: fn(&KeyContext) -> &str = KeyContext::expires_at;
}

#[test]
fn test_online_verification_types_pinned() {
    // Pin GitHubAccount accessors.
    let _id: fn(&GitHubAccount) -> u64 = GitHubAccount::id;
    let _login: fn(&GitHubAccount) -> &str = GitHubAccount::login;
    // Pin GitHubOnlineVerifier method shapes.
    let _verify_ssh_key: fn(
        &GitHubOnlineVerifier,
        &GitHubAccount,
        &str,
    ) -> Result<OnlineVerificationStatus> = GitHubOnlineVerifier::verify_ssh_key;
    let _verify_known_key_candidate: fn(
        &GitHubOnlineVerifier,
        &KnownKeyReviewCandidate,
    ) -> Result<VerifiedGitHubEvidence> = GitHubOnlineVerifier::verify_known_key_candidate;
    let _account: fn(&VerifiedGitHubEvidence) -> &GitHubAccount = VerifiedGitHubEvidence::account;
    let _fingerprint: fn(&VerifiedGitHubEvidence) -> &str = VerifiedGitHubEvidence::fingerprint;
    let _matched_key_id: fn(&VerifiedGitHubEvidence) -> i64 =
        VerifiedGitHubEvidence::matched_key_id;
    // Pin NotConfigured and Failed variant names.
    let _not_configured = OnlineVerificationStatus::NotConfigured;
    let _failed = OnlineVerificationStatus::Failed;
    assert_ne!(_not_configured, OnlineVerificationStatus::Verified);
    assert_ne!(_failed, OnlineVerificationStatus::Verified);
}

#[test]
fn test_operation_options_methods_pinned() {
    let opts = OperationOptions::new().with_allow_expired_key(true);
    assert!(opts.allow_expired_key());
    // Pin method shapes.
    let _with_allow_expired_key: fn(OperationOptions, bool) -> OperationOptions =
        OperationOptions::with_allow_expired_key;
    let _allow_expired_key_getter: fn(&OperationOptions) -> bool =
        OperationOptions::allow_expired_key;
}

#[test]
fn test_diagnostics_take_local_state_warnings_pinned() {
    // Pin the take_local_state_warnings method shape.
    let _take_local_state_warnings: fn() -> DiagnosticBatch =
        kapsaro_core::api::diagnostics::take_local_state_warnings;
    let _code: fn(&LocalStateDiagnostic) -> DiagnosticCode = LocalStateDiagnostic::code;
    let _path: fn(&LocalStateDiagnostic) -> &std::path::Path = LocalStateDiagnostic::path;
    let _reason: fn(&LocalStateDiagnostic) -> &str = LocalStateDiagnostic::reason;
    let _diagnostics: fn(&DiagnosticBatch) -> &[LocalStateDiagnostic] =
        DiagnosticBatch::diagnostics;
    let _into_diagnostics: fn(DiagnosticBatch) -> Vec<LocalStateDiagnostic> =
        DiagnosticBatch::into_diagnostics;
    let _dropped_at_least: fn(DiagnosticTruncation) -> usize =
        DiagnosticTruncation::dropped_at_least;
    let _retained_limit: fn(DiagnosticTruncation) -> usize = DiagnosticTruncation::retained_limit;

    assert_eq!(
        DiagnosticCode::LocalStatePermissions.as_str(),
        "W_LOCAL_STATE_PERMISSIONS"
    );
}

/// A batch taken from a sink nothing wrote to carries no findings and says so.
#[test]
fn test_diagnostics_empty_batch_is_complete() {
    let batch = kapsaro_core::api::diagnostics::take_local_state_warnings();

    assert!(batch.diagnostics().is_empty());
    assert_eq!(batch.completeness(), DiagnosticCompleteness::Complete);
}

/// A keystore whose members are all reachable by other users produces one
/// finding per member, so a wide enough tree passes the bound on what one batch
/// holds. The batch has to say how much it left behind: a capped list that read
/// as the whole of the finding would tell the operator to repair 64 entries and
/// leave the rest of the tree open.
#[cfg(unix)]
#[test]
fn test_diagnostics_batch_past_the_bound_reports_what_it_left_behind() {
    use std::os::unix::fs::PermissionsExt;

    /// Members to install. The batch holds 64, so this leaves a known remainder.
    const MEMBER_COUNT: usize = 70;
    const RETAINED_LIMIT: usize = 64;

    let temp = local_state_tempdir();
    let keystore_root = temp.path().join("keys");
    let key_store = LocalKeyStore::create(&keystore_root).expect("create keystore");
    let member_handles = (0..MEMBER_COUNT)
        .map(|index| {
            let handle = MemberHandle::try_from(format!("member{index:03}@example.com"))
                .expect("valid member handle");
            let member_dir = keystore_root.join(handle.as_str());
            std::fs::create_dir(&member_dir).expect("create member directory");
            let active = member_dir.join("active");
            std::fs::write(&active, "0123456789ABCDEF0123456789ABCDEF").expect("write active kid");
            std::fs::set_permissions(&active, std::fs::Permissions::from_mode(0o600))
                .expect("restrict active marker");
            // The member directory is the single finding this member produces.
            std::fs::set_permissions(&member_dir, std::fs::Permissions::from_mode(0o755))
                .expect("open up member directory");
            handle
        })
        .collect::<Vec<_>>();
    // Reading the members is what records the findings; drop anything the
    // keystore creation itself left in the sink first.
    let _ = kapsaro_core::api::diagnostics::take_local_state_warnings();
    for member_handle in &member_handles {
        key_store
            .load_active_kid(member_handle)
            .expect("read the active marker of an open member directory");
    }

    let batch = kapsaro_core::api::diagnostics::take_local_state_warnings();

    assert_eq!(batch.diagnostics().len(), RETAINED_LIMIT);
    assert!(batch
        .diagnostics()
        .iter()
        .all(|diagnostic| diagnostic.code() == DiagnosticCode::LocalStatePermissions));
    let DiagnosticCompleteness::Truncated(truncation) = batch.completeness() else {
        panic!("a batch that could not hold every finding must say so");
    };
    assert_eq!(truncation.retained_limit(), RETAINED_LIMIT);
    assert_eq!(
        truncation.dropped_at_least(),
        MEMBER_COUNT - RETAINED_LIMIT,
        "the batch must account for every member it could not carry"
    );
}

#[test]
fn test_secret_bytes_into_zeroizing_vec_pinned() {
    let bytes = SecretBytes::new(vec![10, 20, 30]);
    let zv: Zeroizing<Vec<u8>> = bytes.into_zeroizing_vec();
    assert_eq!(zv.as_slice(), &[10, 20, 30][..]);
}

#[test]
fn test_ssh_raw_signature_debug_impl_pinned() {
    let sig = SshRawSignature::new([0u8; 64]);
    let formatted = format!("{sig:?}");
    assert!(formatted.contains("REDACTED"));
}

#[test]
fn test_trust_store_apply_approvals_pinned() {
    // Pin apply_approvals_with_conflict_handling method shape on LocalTrustStore.
    let _apply_approvals_with_conflict_handling: fn(
        &LocalTrustStore,
        Vec<TrustApproval>,
        &KeyContext,
        ApprovalConflictHandling,
    ) -> Result<TrustApprovalOutcome> = LocalTrustStore::apply_approvals_with_conflict_handling;
    let _applied: fn(&TrustApprovalOutcome) -> usize = TrustApprovalOutcome::applied;
    let _warnings: fn(&TrustApprovalOutcome) -> &DiagnosticBatch = TrustApprovalOutcome::warnings;
    let _merge: fn() -> ApprovalConflictHandling = ApprovalConflictHandling::merge;
    let _surface: fn(&VerifiedLocalTrustStoreLoadResult) -> ApprovalConflictHandling =
        ApprovalConflictHandling::surface;
    let _surface_absent: fn() -> ApprovalConflictHandling =
        ApprovalConflictHandling::surface_absent;
}

#[test]
fn test_recipient_set_subject_accessors_pinned() {
    let _sid: fn(&RecipientSetSubject) -> uuid::Uuid = RecipientSetSubject::sid;
    let _recipient_kids: fn(&RecipientSetSubject) -> &[Kid] = RecipientSetSubject::recipient_kids;
}

#[test]
fn test_trust_review_request_accessors_pinned() {
    // Pin review evidence accessors on TrustReviewRequest.
    let _subject_handle_fn: fn(&TrustReviewRequest) -> Option<&MemberHandle> =
        TrustReviewRequest::subject_handle;
    let _kid_fn: fn(&TrustReviewRequest) -> Option<&Kid> = TrustReviewRequest::kid;
    let _candidate_fn: fn(&TrustReviewRequest) -> Option<&KnownKeyReviewCandidate> =
        TrustReviewRequest::known_key_candidate;
    let _candidate_fingerprint: fn(&KnownKeyReviewCandidate) -> Option<&str> =
        KnownKeyReviewCandidate::fingerprint;
    let _sid_fn: fn(&TrustReviewRequest) -> Option<uuid::Uuid> = TrustReviewRequest::sid;
    let _recipient_kids_fn: fn(&TrustReviewRequest) -> &[Kid] = TrustReviewRequest::recipient_kids;
    let _recipient_handle_hints_fn: fn(&TrustReviewRequest) -> &[TrustRecipientHandleHint] =
        TrustReviewRequest::recipient_handle_hints;
}

#[test]
fn test_trust_review_kind_variants_pinned() {
    // Name all three variants to ensure RecipientSet and ChangedRecipientSet are reachable.
    let kinds = [
        TrustReviewKind::KnownKey,
        TrustReviewKind::RecipientSet,
        TrustReviewKind::ChangedRecipientSet,
    ];
    assert_eq!(kinds.len(), 3);
}

#[test]
fn test_trust_approval_constructors_and_from_request_pinned() {
    let evidence =
        KnownKeyApprovalEvidence::none().with_ssh_attestor_public_key("ssh-ed25519 AAAA");
    assert!(std::any::type_name::<TrustApproval>().contains("TrustApproval"));
    assert!(std::any::type_name::<KnownKeyReviewCandidate>().contains("KnownKeyReviewCandidate"));
    drop(evidence);
    let _known_key: fn(
        &KnownKeyReviewCandidate,
        KnownKeyApprovalEvidence,
    ) -> Result<TrustApproval> = TrustApproval::known_key;
    let _recipient_set: fn(
        uuid::Uuid,
        Vec<Kid>,
        Vec<TrustRecipientHandleHint>,
    ) -> Result<TrustApproval> = TrustApproval::recipient_set;
}

#[test]
fn test_read_trust_exceptions_are_explicit_and_consumed() {
    let exceptions = ReadTrustExceptions::none()
        .with_known_key_review(KnownKeyReview::Skipped)
        .accepting_non_member(
            MemberHandle::new("alice@example.com").expect("valid member handle"),
            Kid::new("0123456789ABCDEFGHJKMNPQRSTVWXYZ").expect("canonical kid"),
        );
    assert!(format!("{exceptions:?}").contains("ReadTrustExceptions"));
}

#[test]
fn test_verified_local_trust_store_load_result_pinned() {
    // Pin VerifiedLocalTrustStoreLoadResult type and its two public methods.
    assert!(std::any::type_name::<VerifiedLocalTrustStoreLoadResult>()
        .contains("VerifiedLocalTrustStoreLoadResult"));
    let _into_store: fn(VerifiedLocalTrustStoreLoadResult) -> VerifiedLocalTrustStore =
        VerifiedLocalTrustStoreLoadResult::into_store;
}

/// The rule and the recovery route are separate axes and are pinned as such: a
/// failure names the check it was refused under, the route out of it, or both,
/// and reading one never depends on the other being absent.
#[test]
fn test_error_rule_and_recovery_accessors_pinned() {
    let _rule: fn(&Error) -> Option<&str> = Error::rule;
    let _recovery: fn(&Error) -> Option<&'static str> = Error::recovery;

    // A verification failure names its rule and no recovery route.
    let verification = Error::build_verification_error("V-TOFU", "msg");
    assert_eq!(verification.rule(), Some("V-TOFU"));
    assert_eq!(verification.recovery(), None);

    // Every other category names no rule at all.
    assert_eq!(Error::build_parse_error("msg").rule(), None);
    assert_eq!(Error::build_config_error("msg").rule(), None);
    assert_eq!(Error::build_invalid_operation_error("msg").rule(), None);
}

#[test]
fn test_error_builder_methods_pinned() {
    // rule accessor.
    let ve = Error::build_verification_error("RULE", "msg");
    assert_eq!(ve.rule(), Some("RULE"));
    // All builder functions.
    let _e1 = Error::build_schema_error("schema problem");
    assert_eq!(_e1.kind(), ErrorKind::Schema);
    let _e2 = Error::build_schema_error_with_source("schema with source", std::fmt::Error);
    assert_eq!(_e2.kind(), ErrorKind::Schema);
    let _e3 = Error::build_verification_error("R", "v");
    assert_eq!(_e3.kind(), ErrorKind::Verify);
    let _e4 = Error::build_parse_error("parse problem");
    assert_eq!(_e4.kind(), ErrorKind::Parse);
    let _e5 = Error::build_parse_error_with_source("parse with source", std::fmt::Error);
    assert_eq!(_e5.kind(), ErrorKind::Parse);
    let _e6 = Error::build_config_error("config problem");
    assert_eq!(_e6.kind(), ErrorKind::Config);
    let _e7 = Error::build_not_found_error("not found");
    assert_eq!(_e7.kind(), ErrorKind::NotFound);
    let _e8 = Error::build_invalid_operation_error("invalid op");
    assert_eq!(_e8.kind(), ErrorKind::InvalidOperation);
    let _e9 = Error::build_crypto_error("crypto problem");
    assert_eq!(_e9.kind(), ErrorKind::Crypto);
    let _e10 = Error::build_crypto_error_with_source("crypto with source", std::fmt::Error);
    assert_eq!(_e10.kind(), ErrorKind::Crypto);
    let _e11 = Error::build_io_error("io problem");
    assert_eq!(_e11.kind(), ErrorKind::Io);
    let io_src = std::io::Error::other("src");
    let _e12 = Error::build_io_error_with_source("io with source", io_src);
    assert_eq!(_e12.kind(), ErrorKind::Io);
    let _e13 = Error::build_ssh_error("ssh problem");
    assert_eq!(_e13.kind(), ErrorKind::Ssh);
    let _e14 = Error::build_ssh_error_with_source("ssh with source", std::fmt::Error);
    assert_eq!(_e14.kind(), ErrorKind::Ssh);
}

#[test]
fn test_error_trait_impls_pinned() {
    // Display impl.
    let e = Error::build_crypto_error("kdf failure");
    let display = format!("{e}");
    assert!(display.contains("kdf failure"));
    // std::error::Error::source — should return None for plain crypto error.
    let source = StdError::source(&e);
    assert!(source.is_none());
    // source is Some when built with a source error.
    let e_with_src = Error::build_crypto_error_with_source("outer", std::fmt::Error);
    assert!(StdError::source(&e_with_src).is_some());
    // From<std::io::Error>.
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
    let converted: Error = Error::from(io_err);
    assert_eq!(converted.kind(), ErrorKind::Io);
    // From<serde_json::Error>.
    let json_err: serde_json::Error =
        serde_json::from_str::<serde_json::Value>("{bad}").expect_err("must fail");
    let converted_json: Error = Error::from(json_err);
    assert_eq!(converted_json.kind(), ErrorKind::Parse);
    // From<hkdf::InvalidLength> — hkdf is a regular dependency, accessible here.
    let hkdf_err = hkdf::InvalidLength;
    let converted_hkdf: Error = Error::from(hkdf_err);
    assert_eq!(converted_hkdf.kind(), ErrorKind::Crypto);
}

#[test]
fn test_error_kind_all_variants_pinned() {
    // Exercise every ErrorKind variant in a match to ensure each is reachable.
    let all_kinds = [
        ErrorKind::Schema,
        ErrorKind::Crypto,
        ErrorKind::Ssh,
        ErrorKind::Verify,
        ErrorKind::Io,
        ErrorKind::Parse,
        ErrorKind::Config,
        ErrorKind::NotFound,
        ErrorKind::InvalidOperation,
        ErrorKind::InvalidArgument,
    ];
    for kind in all_kinds {
        match kind {
            ErrorKind::Schema
            | ErrorKind::Crypto
            | ErrorKind::Ssh
            | ErrorKind::Verify
            | ErrorKind::Io
            | ErrorKind::Parse
            | ErrorKind::Config
            | ErrorKind::NotFound
            | ErrorKind::InvalidOperation
            | ErrorKind::InvalidArgument => {}
        }
    }
    assert_eq!(all_kinds.len(), 10);
}
