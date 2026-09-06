// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use kapsaro_core::api::config::LocalStateSession;
use kapsaro_core::api::diagnostics::{
    DiagnosticBatch, DiagnosticCode, DiagnosticCompleteness, DiagnosticTruncation,
    LocalStateDiagnostic,
};
use kapsaro_core::api::doctor::{
    execute_doctor_command, DoctorCiReadiness, DoctorRequest, DoctorStrictKeyChecking,
    DoctorWorkspaceResolution, DoctorWorkspaceSource,
};
use kapsaro_core::api::file::encrypt::{resolve_encrypt_file_command, EncryptFileCommand};
use kapsaro_core::api::file::{
    load_plaintext_bytes, save_decrypted_bytes, save_encrypted_text, FileEncArtifact,
    FileReadOperation, TrustedFileEncArtifact, VerifiedFileEncArtifact,
};
use kapsaro_core::api::key::generate::KeyGenerationHome;
use kapsaro_core::api::key::{
    format_kid_display, format_kid_display_lossy, load_environment_key, save_private_export_text,
    validate_github_login, KeyContext, KeyContextOptions, Kid, LocalKeyContextRequest,
    LocalKeyStore, MemberHandle, RecipientKeys,
};
use kapsaro_core::api::kv::mutation::{resolve_mutation_write_plan, MutationWriteTrustPlan};
use kapsaro_core::api::kv::{
    load_import_text, AuthorizedKvMutation, KvDisclosedEntry, KvEncArtifact, KvGetResult,
    KvInputEntry, KvMutationOperation, KvReadOperation, TrustedKvEncArtifact,
    VerifiedKvEncArtifact,
};
use kapsaro_core::api::online::{
    GitHubAccount, GitHubOnlineVerifier, OnlineVerificationStatus, VerifiedGitHubEvidence,
};
use kapsaro_core::api::operation::OperationOptions;
use kapsaro_core::api::process::remove_parent_kapsaro_env_vars;
use kapsaro_core::api::rewrap::{
    AuthorizedRewrapInput, RewrapOptions, RewrapReview, RewrapSession, RewrapTarget,
};
use kapsaro_core::api::secret::{SecretBytes, SecretString};
use kapsaro_core::api::ssh::{
    build_ssh_signing_context, resolve_ssh_agent_socket, resolve_ssh_key_candidates,
    SshRawSignature, SshSignatureBackend, SshSigningInputs, SshSigningMethod,
};
use kapsaro_core::api::trust::{
    ApprovalConflictHandling, CurrentMemberSnapshot, KnownKeyApprovalEvidence, KnownKeyReview,
    KnownKeyReviewCandidate, LocalTrustStore, ReadReview, ReadTrustExceptions, RecipientSetSubject,
    TrustApproval, TrustApprovalOutcome, TrustCommandSession, TrustPolicyEvaluator,
    TrustRecipientHandleHint, TrustReviewKind, TrustReviewRequest, VerifiedLocalTrustStore,
    VerifiedLocalTrustStoreLoadResult, WorkspaceReadSession,
};
use kapsaro_core::api::workspace::{WorkspaceWriteDirectories, SECRETS_DIR_NAME};
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
    let key_store = LocalKeyStore::ensure(temp.path().join("keys")).expect("create keystore");
    let trust_store = LocalTrustStore::open(temp.path(), member_handle).expect("open trust store");
    let _signature = kapsaro_core::api::ssh::SshRawSignature::new([3u8; 64]);
    let _secret = kapsaro_core::api::secret::SecretString::new("secret".to_string());
    let _bytes = kapsaro_core::api::secret::SecretBytes::new(vec![1, 2, 3]);
    let _options = kapsaro_core::api::operation::OperationOptions::default();
    let _online = kapsaro_core::api::online::GitHubOnlineVerifier::new();
    let _warnings = kapsaro_core::api::diagnostics::take_local_state_warnings();
    let local_state = LocalStateSession::open(temp.path()).expect("open local state session");
    let _config = local_state.load_config().expect("load global config");

    assert_eq!(key_store.root(), temp.path().join("keys").as_path());
    assert_eq!(
        trust_store.path(),
        temp.path().join("trust/alice@example.com.json")
    );
}

#[test]
fn test_doctor_request_exposes_caller_resolved_workspace() {
    let workspace = DoctorWorkspaceResolution::Selection {
        path: std::path::PathBuf::from("/tmp/workspace"),
        source: DoctorWorkspaceSource::Cli,
    };
    let _request = DoctorRequest {
        base_dir: std::path::PathBuf::from("/tmp/home"),
        workspace,
        member_handle: None,
        ci: DoctorCiReadiness::Inactive,
    };
    let _execute: fn(DoctorRequest) -> Result<kapsaro_core::api::doctor::types::DoctorReport> =
        execute_doctor_command;
    let _unresolved = DoctorWorkspaceResolution::Unresolved;
    let _failure = DoctorWorkspaceResolution::Failure(Error::build_config_error("failure"));
    let _sources = [
        DoctorWorkspaceSource::Cli,
        DoctorWorkspaceSource::Environment,
        DoctorWorkspaceSource::Config,
        DoctorWorkspaceSource::AutoDetect,
    ];
}

#[test]
fn test_doctor_strict_key_checking_states_are_public() {
    let _states = [
        DoctorStrictKeyChecking::Enabled,
        DoctorStrictKeyChecking::Disabled,
        DoctorStrictKeyChecking::Invalid("value cannot be read".to_string()),
    ];
    let _readiness = DoctorCiReadiness::Active {
        strict_key_checking: DoctorStrictKeyChecking::Enabled,
        private_key_error: None,
    };
}

#[test]
fn test_kid_display_and_github_login_validation_are_public() {
    let _format: fn(&str) -> Result<String> = format_kid_display;
    let _lossy: fn(&str) -> String = format_kid_display_lossy;
    let _validate: fn(&str) -> Result<()> = validate_github_login;

    assert_eq!(
        format_kid_display("0123456789ABCDEFGHJKMNPQRSTVWXYZ").expect("valid kid"),
        "0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ"
    );
    validate_github_login("alice-example").expect("valid GitHub login");
}

#[test]
fn test_child_process_environment_isolation_is_public() {
    let _remove: fn(&mut std::process::Command) = remove_parent_kapsaro_env_vars;
}

#[test]
fn test_secrets_directory_name_is_public() {
    let _name: &str = SECRETS_DIR_NAME;

    assert_eq!(SECRETS_DIR_NAME, "secrets");
}

#[test]
fn test_local_state_facade_debug_names_only_the_facade() {
    let temp = local_state_tempdir();
    let member_handle = MemberHandle::try_from("alice@example.com").expect("valid member handle");
    let key_store = LocalKeyStore::ensure(temp.path().join("keys")).expect("create keystore");
    let trust_store = LocalTrustStore::open(temp.path(), member_handle).expect("open trust store");

    assert_eq!(format!("{key_store:?}"), "LocalKeyStore { .. }");
    assert_eq!(format!("{trust_store:?}"), "LocalTrustStore { .. }");
}

#[test]
fn key_context_options_group_runtime_inputs() {
    let member_handle = MemberHandle::try_from("alice@example.com").expect("valid member handle");
    let _options = KeyContextOptions::new(
        member_handle.clone(),
        Box::new(StubSshBackend),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA".to_string(),
    )
    .with_kid(Kid::try_from("0123456789ABCDEFGHJKMNPQRSTVWXYZ").expect("valid kid"));

    let _load_key_context = LocalKeyStore::load_key_context;
    let _load_selected_key_context = LocalKeyStore::load_selected_key_context;
    let _resolve_signing_context = LocalKeyStore::resolve_signing_context;
    let _load_environment_key = KeyContext::load_environment_key;
    let _load_environment_key = load_environment_key;
    let _ssh_inputs = SshSigningInputs::new(
        SshSigningMethod::SshAgent,
        None,
        Some(std::path::PathBuf::from("/tmp/agent.sock")),
        "ssh-keygen",
        "ssh-add",
    );
    let _request = LocalKeyContextRequest::new(member_handle, _ssh_inputs)
        .with_kid(Kid::try_from("0123456789ABCDEFGHJKMNPQRSTVWXYZ").expect("valid kid"));
    let _list_ssh_candidates = resolve_ssh_key_candidates;
    let _build_ssh_context = build_ssh_signing_context;
    type ResolveSshAgentSocket = fn(
        Option<&std::path::Path>,
        Option<std::path::PathBuf>,
        &std::collections::BTreeMap<String, String>,
    ) -> Result<Option<std::path::PathBuf>>;
    let _resolve_ssh_agent_socket: ResolveSshAgentSocket = resolve_ssh_agent_socket;
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
        LocalTrustStore::ensure;
    let _load_verified = LocalTrustStore::load_verified;
}

#[test]
fn missing_trust_store_loads_as_none() {
    let temp = local_state_tempdir();
    let member_handle = MemberHandle::try_from("alice@example.com").expect("valid member handle");
    let key_store = LocalKeyStore::ensure(temp.path().join("keys")).expect("create keystore");
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
    assert_eq!(
        OnlineVerificationStatus::Verified,
        OnlineVerificationStatus::Verified
    );
    assert!(OnlineVerificationStatus::Verified.is_verified());
}

#[test]
fn artifact_io_helpers_are_available_through_purpose_specific_modules() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let plaintext_path = temp.path().join("plaintext");
    std::fs::write(&plaintext_path, b"secret").expect("write plaintext fixture");

    assert_eq!(
        load_plaintext_bytes(&plaintext_path).expect("load plaintext"),
        b"secret"
    );

    let encrypted_path = temp.path().join("artifact.kapsaro");
    save_encrypted_text(&encrypted_path, "encrypted").expect("save encrypted artifact");
    assert_eq!(
        std::fs::read_to_string(encrypted_path).expect("read encrypted artifact"),
        "encrypted"
    );

    let decrypted_path = temp.path().join("decrypted");
    save_decrypted_bytes(&decrypted_path, b"decrypted").expect("save decrypted artifact");
    assert_eq!(
        std::fs::read(decrypted_path).expect("read decrypted artifact"),
        b"decrypted"
    );

    let import_path = temp.path().join("import.env");
    std::fs::write(&import_path, "KEY=value\n").expect("write import fixture");
    assert_eq!(
        load_import_text(&import_path).expect("load import text"),
        "KEY=value\n"
    );

    let export_path = temp.path().join("private-key.json");
    save_private_export_text(&export_path, "protected").expect("save private export");
    assert_eq!(
        std::fs::read_to_string(export_path).expect("read private export"),
        "protected"
    );
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
    let _encrypt_entries: fn(
        Vec<KvInputEntry>,
        &RecipientKeys,
        &KeyContext,
    ) -> Result<KvEncArtifact> = KvEncArtifact::encrypt_entries;
    let _list_entry_keys = TrustedKvEncArtifact::list_entry_keys;
    let _decrypt_entry = TrustedKvEncArtifact::decrypt_entry;
    let _decrypt_entries = TrustedKvEncArtifact::decrypt_entries;
    let _decrypt_environment = TrustedKvEncArtifact::decrypt_environment;
    let _get_result = TrustedKvEncArtifact::get_result;
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
}

#[test]
fn test_workspace_write_directories_and_resolvers_are_public() {
    fn open_directories(path: std::path::PathBuf) -> Result<WorkspaceWriteDirectories> {
        WorkspaceWriteDirectories::open(path)
    }

    fn resolve_encrypt<'a>(
        directories: &'a WorkspaceWriteDirectories,
        trust: &'a TrustCommandSession,
        options: kapsaro_core::api::trust::WriteTrustOptions,
        input: Vec<u8>,
    ) -> Result<EncryptFileCommand<'a>> {
        resolve_encrypt_file_command(directories, trust, options, input)
    }

    fn resolve_mutation<'a>(
        directories: &'a WorkspaceWriteDirectories,
        trust: &'a TrustCommandSession,
        options: kapsaro_core::api::trust::WriteTrustOptions,
        file_name: Option<&str>,
        allow_missing: bool,
    ) -> Result<MutationWriteTrustPlan<'a>> {
        resolve_mutation_write_plan(directories, trust, options, file_name, allow_missing)
    }

    let _open_directories = open_directories;
    let _resolve_encrypt = resolve_encrypt;
    let _resolve_mutation = resolve_mutation;
}

#[test]
fn trust_evaluator_exposes_operation_bound_decisions() {
    fn open_rewrap_session<'a>(
        workspace: &std::path::Path,
        home: Option<std::path::PathBuf>,
        key_ctx: &'a KeyContext,
    ) -> Result<RewrapSession<'a>> {
        RewrapSession::open(workspace, home, key_ctx)
    }

    fn open_rewrap_with_trust<'a>(
        workspace: &std::path::Path,
        trust: &'a TrustCommandSession,
    ) -> Result<RewrapSession<'a>> {
        RewrapSession::from_trust_command(workspace, trust)
    }

    let _load_snapshot = CurrentMemberSnapshot::load;
    let _evaluate_file = TrustPolicyEvaluator::evaluate_file;
    let _evaluate_kv = TrustPolicyEvaluator::evaluate_kv;
    let _evaluate_kv_mutation = TrustPolicyEvaluator::evaluate_kv_mutation;
    let _rewrite = AuthorizedRewrapInput::rewrite;
    let _publish = AuthorizedRewrapInput::publish;
    let _rewrap_options = RewrapOptions::new();
    let _open_rewrap_session = open_rewrap_session;
    let _open_rewrap_with_trust = open_rewrap_with_trust;
    let _open_rewrap_target = |path: &std::path::Path| RewrapTarget::open(path);
    let _workspace_rewrap_target = RewrapSession::workspace_target;
    let _list_workspace_targets = RewrapSession::list_workspace_targets;
    let _post_promotion_warnings = RewrapSession::post_promotion_warnings;
    let _signing_key_warnings = RewrapSession::signing_key_warnings;
    let _begin_promotion_review = RewrapSession::begin_promotion_review;
    let _apply_promotions = RewrapSession::apply_promotions;
    let _apply_rewrap_approvals = RewrapSession::apply_approvals;
    let _apply_rewrap_review_approval = RewrapSession::apply_review_approval;
    let _begin_rewrap = RewrapSession::begin_rewrap;
    let _resume_rewrap = RewrapSession::resume_rewrap;
    let _accept_non_member_rewrap = RewrapReview::accept_non_member;
    let _rewrap_signer_first = RewrapReview::first_request_is_signer;
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
    let _key_fn: fn(&KvDisclosedEntry) -> &str = KvDisclosedEntry::key;
    let _disclosed_fn: fn(&KvDisclosedEntry) -> bool = KvDisclosedEntry::disclosed;
    let _values = KvGetResult::values;
    let _disclosed_entries = KvGetResult::disclosed_entries;
    let _into_parts = KvGetResult::into_parts;
}

#[test]
fn test_local_key_store_methods_pinned() {
    // Pin construction and member-handle-bound method shapes.
    let _open: fn(std::path::PathBuf) -> Result<LocalKeyStore> = LocalKeyStore::open;
    let _create: fn(std::path::PathBuf) -> Result<LocalKeyStore> = LocalKeyStore::ensure;
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
    let ks = LocalKeyStore::ensure(temp.path().join("keys")).expect("create keystore");
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
    let key_store = LocalKeyStore::ensure(&keystore_root).expect("create keystore");
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
    let _approved_recipient_set_fn: fn(
        &TrustReviewRequest,
    ) -> Option<
        &kapsaro_core::api::trust::enforcement::ArtifactRecipientSetSnapshot,
    > = TrustReviewRequest::approved_recipient_set;
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
fn test_read_session_types_and_low_level_review_control_are_public() {
    fn open_session<'a>(
        workspace: &std::path::Path,
        local_state: Option<&LocalStateSession>,
        key_context: &'a KeyContext,
        options: OperationOptions,
    ) -> Result<WorkspaceReadSession<'a>> {
        WorkspaceReadSession::open_with_local_state(workspace, local_state, key_context, options)
    }

    let exceptions = ReadTrustExceptions::none().with_known_key_review(KnownKeyReview::Skipped);
    assert!(format!("{exceptions:?}").contains("ReadTrustExceptions"));
    let _requests = ReadReview::requests;
    let _first_request_is_signer = ReadReview::first_request_is_signer;
    let _non_member_signer = ReadReview::non_member_signer;
    let _accept_non_member = ReadReview::accept_non_member;
    let _open_with_local_state = open_session;
    let _with_known_key_review = WorkspaceReadSession::with_known_key_review;
    let _observe_recovery = WorkspaceReadSession::observe_trust_store_recovery;
    let _build_reset_plan = WorkspaceReadSession::build_trust_store_reset_plan;
}

#[test]
fn test_key_generation_home_uses_a_fixed_local_state_session() {
    let _fix: fn(&LocalStateSession) -> Result<KeyGenerationHome> = KeyGenerationHome::fix;
}

#[test]
fn test_verified_local_trust_store_load_result_pinned() {
    // Pin VerifiedLocalTrustStoreLoadResult type and its two public methods.
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

/// Every name the `api` facade re-exports, imported anonymously.
///
/// The imports are the assertion: drop one `pub use` from `api` and this
/// module stops compiling, so the facade cannot shrink unnoticed.
#[allow(unused_imports)]
mod every_public_name {
    use kapsaro_core::api::config::{
        list_config as _, resolve_config_value as _, set_config as _, unset_config as _,
        ConfigScope as _, ConfigSetResult as _, ConfigUnsetResult as _, LocalStateSession as _,
    };
    use kapsaro_core::api::diagnostics::{
        take_local_state_warnings as _, DiagnosticBatch as _, DiagnosticCode as _,
        DiagnosticCompleteness as _, DiagnosticTruncation as _, LocalStateDiagnostic as _,
    };
    use kapsaro_core::api::doctor::types::{
        DoctorCategory as _, DoctorCheck as _, DoctorReason as _, DoctorReport as _,
        DoctorStatus as _, DoctorSubject as _,
    };
    use kapsaro_core::api::doctor::{
        execute_doctor_command as _, DoctorCiReadiness as _, DoctorRequest as _,
        DoctorStrictKeyChecking as _, DoctorWorkspaceResolution as _, DoctorWorkspaceSource as _,
    };
    use kapsaro_core::api::file::encrypt::{
        execute_encrypt_file_command_with_recipient_set_confirmation as _,
        resolve_encrypt_file_command as _, EncryptFileCommand as _,
    };
    use kapsaro_core::api::file::{
        load_plaintext_bytes as _, save_decrypted_bytes as _, save_encrypted_text as _,
        FileEncArtifact as _, FileReadOperation as _, TrustedFileEncArtifact as _,
        VerifiedFileEncArtifact as _,
    };
    use kapsaro_core::api::inspect::{
        inspect_file as _, AeadAlgorithmMetadata as _, ArtifactSignatureMetadata as _,
        AttestationMetadata as _, BindingClaimsMetadata as _, FileEncHeaderMetadata as _,
        FileEncInspectMetadata as _, FilePayloadMetadata as _, FilePayloadProtectedMetadata as _,
        GithubAccountMetadata as _, IdentityKeysMetadata as _, InspectMetadata as _,
        InspectResult as _, JwkPublicKeyMetadata as _, KvEncInspectMetadata as _,
        KvEntryMetadata as _, KvHeaderMetadata as _, KvSummaryMetadata as _,
        OnlineVerificationMetadata as _, PayloadCiphertextMetadata as _,
        RemovedRecipientMetadata as _, SignatureVerificationMetadata as _,
        SignerPublicKeyMetadata as _, SignerPublicKeyProtectedMetadata as _, WrapDataMetadata as _,
        WrapItemMetadata as _,
    };
    use kapsaro_core::api::key::generate::{
        generate_key_command as _, KeyExpiryRequest as _, KeyGenerationHome as _,
    };
    use kapsaro_core::api::key::manage::{
        activate_key_command as _, export_key_command as _, export_private_key_command as _,
        list_keys_command as _, remove_key_command as _,
    };
    use kapsaro_core::api::key::types::{
        KeyActivateResult as _, KeyExportPrivateResult as _, KeyExportResult as _,
        KeyGenerationResult as _, KeyInfo as _, KeyListResult as _, KeyRemoveResult as _,
        MissingKeyDocument as _,
    };
    use kapsaro_core::api::key::{
        build_missing_member_handle_error as _, format_kid_display as _,
        format_kid_display_lossy as _, load_environment_key as _,
        parse_relative_duration_days as _, save_private_export_text as _,
        validate_github_login as _, KeyContext as _, KeyContextOptions as _, Kid as _,
        LocalKeyContextRequest as _, LocalKeyStore as _, MemberHandle as _, RecipientKeys as _,
    };
    use kapsaro_core::api::kv::mutation::{
        import_kv_command_with_recipient_set_confirmation as _,
        reevaluate_mutation_write_plan_after_review as _, resolve_mutation_write_plan as _,
        set_kv_command_with_recipient_set_confirmation as _,
        unset_kv_command_with_recipient_set_confirmation as _, MutationWriteTrustPlan as _,
    };
    use kapsaro_core::api::kv::{
        is_missing_key_error as _, load_import_text as _, resolve_kv_store_file_name as _,
        AuthorizedKvMutation as _, KvDisclosedEntry as _, KvEncArtifact as _, KvGetResult as _,
        KvInputEntry as _, KvMutationOperation as _, KvReadOperation as _,
        TrustedKvEncArtifact as _, VerifiedKvEncArtifact as _,
    };
    use kapsaro_core::api::member::approval::{
        evaluate_members_for_approval as _, save_member_approvals as _,
        MemberApprovalEvaluation as _, MemberApprovalResult as _, MemberApprovalSession as _,
    };
    use kapsaro_core::api::member::mutation::{
        add_member as _, evaluate_member_removal as _, remove_member as _,
    };
    use kapsaro_core::api::member::query::{list_members as _, load_member_show_result as _};
    use kapsaro_core::api::member::types::{
        MemberDocumentStatus as _, MemberDocumentView as _, MemberGithubClaim as _,
        MemberListEntry as _, MemberListResult as _, MemberRemovalReport as _,
        MemberRemoveResult as _, MemberShowResult as _, MemberVerificationResult as _,
        MembershipStatus as _,
    };
    use kapsaro_core::api::member::verification::evaluate_members_online as _;
    use kapsaro_core::api::online::{
        GitHubAccount as _, GitHubOnlineVerifier as _, OnlineVerificationStatus as _,
        VerifiedGitHubEvidence as _,
    };
    use kapsaro_core::api::operation::OperationOptions as _;
    use kapsaro_core::api::process::remove_parent_kapsaro_env_vars as _;
    use kapsaro_core::api::registration::command::{
        evaluate_registration_decision as _, execute_registration_decision as _,
        resolve_registration_command as _, RegistrationDecision as _,
    };
    use kapsaro_core::api::registration::key_plan::{
        open_registration_local_state as _, RegistrationLocalState as _,
    };
    use kapsaro_core::api::registration::types::{
        MemberKeySetupResult as _, RegistrationCommand as _, RegistrationKeyPlan as _,
        RegistrationMode as _, RegistrationOutcome as _, RegistrationResult as _,
        RegistrationTarget as _,
    };
    use kapsaro_core::api::registration::{
        ensure_init_workspace_structure as _, evaluate_init_workspace_status as _,
        InitWorkspaceState as _,
    };
    use kapsaro_core::api::rewrap::promotion::{
        PromotionReviewFailure as _, PromotionReviewPrompt as _, PromotionReviewView as _,
    };
    use kapsaro_core::api::rewrap::{
        AuthorizedRewrapInput as _, RewrapAcceptance as _, RewrapDirectories as _,
        RewrapNonMemberReview as _, RewrapOptions as _, RewrapPromotionOutcome as _,
        RewrapPromotionReview as _, RewrapReview as _, RewrapSession as _,
        RewrapSessionDecision as _, RewrapTarget as _, RewrapTargetListing as _,
    };
    use kapsaro_core::api::secret::{SecretBytes as _, SecretString as _};
    use kapsaro_core::api::ssh::{
        build_ssh_signing_context as _, resolve_ssh_agent_socket as _,
        resolve_ssh_key_candidates as _, SshDeterminismStatus as _, SshKeyCandidateView as _,
        SshRawSignature as _, SshSignatureBackend as _, SshSigningContextResolution as _,
        SshSigningInputs as _, SshSigningMethod as _,
    };
    use kapsaro_core::api::trust::enforcement::{
        ArtifactRecipientHandleHint as _, ArtifactRecipientSetReview as _,
        ArtifactRecipientSetSnapshot as _,
    };
    use kapsaro_core::api::trust::list::{
        list_known_keys_command as _, list_recipient_sets_command as _,
        resolve_trust_list_command as _, RecipientSetListItem as _, RecipientSetListResult as _,
        TrustListCommand as _, TrustListItem as _, TrustListResult as _,
    };
    use kapsaro_core::api::trust::management::{
        execute_purge as _, execute_recipient_set_purge as _, list_purge_candidates as _,
        list_recipient_set_purge_candidates as _, remove_known_key_command as _,
        remove_recipient_set_command as _, PurgeOutcome as _, ReviewedPurgeCandidates as _,
    };
    use kapsaro_core::api::trust::recovery::{
        build_trust_store_reset_plan_from_list_command as _,
        build_trust_store_reset_plan_from_session as _, evaluate_trust_store_reset as _,
        execute_trust_store_reset as _, observe_trust_store_recovery_from_list_command as _,
        observe_trust_store_recovery_from_session as _, TrustStoreRecoveryToken as _,
        TrustStoreResetCause as _, TrustStoreResetLoss as _, TrustStoreResetPlan as _,
    };
    use kapsaro_core::api::trust::resign::{
        resign_trust_store_command as _, TrustStoreResignResult as _,
    };
    use kapsaro_core::api::trust::review::{
        execute_read_with_signer_trust as _, review_write_recipient_trust as _,
        ReadSignerTrustReviewPlan as _, ReadTrustConfirmations as _, SignerTrustLabels as _,
        TrustReviewContext as _, WriteRecipientTrustReviewPlan as _,
    };
    use kapsaro_core::api::trust::{
        ApprovalConflictHandling as _, ArtifactRecipientTrustOutcome as _, AuthorizedRead as _,
        CurrentMemberSnapshot as _, FileReadTarget as _, KnownKeyApprovalEvidence as _,
        KnownKeyReview as _, KnownKeyReviewCandidate as _, LocalTrustStore as _,
        NonMemberReadReview as _, ReadAcceptance as _, ReadReview as _, ReadSessionDecision as _,
        ReadTrustExceptions as _, RecipientSetSubject as _, RecipientTrustOutcome as _,
        SignerTrustOutcome as _, StrictKeyChecking as _, StrictKeyCheckingResolution as _,
        StrictKeyCheckingSource as _, TrustApproval as _, TrustApprovalCandidate as _,
        TrustApprovalOutcome as _, TrustCommandSession as _, TrustDecision as _,
        TrustPolicyEvaluator as _, TrustRecipientHandleHint as _, TrustReviewKind as _,
        TrustReviewRequest as _, VerifiedLocalTrustStore as _,
        VerifiedLocalTrustStoreLoadResult as _, WorkspaceReadDirectories as _,
        WorkspaceReadSession as _, WriteTrustOptions as _,
    };
    use kapsaro_core::api::workspace::{
        detect_workspace_path as _, resolve_workspace_path as _,
        select_workspace_creation_path as _, WorkspaceWriteDirectories as _, SECRETS_DIR_NAME as _,
    };
}
