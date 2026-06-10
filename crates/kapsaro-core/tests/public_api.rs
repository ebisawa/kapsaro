// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use kapsaro_core::api::file::{FileEncArtifact, VerifiedFileEncArtifact};
use kapsaro_core::api::key::{KeyContext, KeyContextOptions, LocalKeyStore, RecipientKeys};
use kapsaro_core::api::kv::{KvDisclosedEntry, KvEncArtifact, KvInputEntry, VerifiedKvEncArtifact};
use kapsaro_core::api::online::{
    GitHubAccount, GitHubOnlineVerifier, OnlineVerificationResult, OnlineVerificationStatus,
};
use kapsaro_core::api::operation::OperationOptions;
use kapsaro_core::api::secret::{SecretBytes, SecretString};
use kapsaro_core::api::ssh::{SshRawSignature, SshSignatureBackend};
use kapsaro_core::api::trust::{
    LocalTrustStore, RecipientSetSubject, TrustApproval, TrustDecision, TrustPolicyEvaluator,
    TrustReviewKind, TrustReviewRequest, VerifiedLocalTrustStore,
    VerifiedLocalTrustStoreLoadResult,
};
use kapsaro_core::{Error, ErrorKind, Result};
use std::error::Error as StdError;
use zeroize::Zeroizing;

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
    let temp = tempfile::tempdir().expect("tempdir");
    let key_store = LocalKeyStore::new(temp.path().join("keys"));
    let trust_store = LocalTrustStore::new(temp.path(), "alice@example.com".to_string());
    let _signature = kapsaro_core::api::ssh::SshRawSignature::new([3u8; 64]);
    let _secret = kapsaro_core::api::secret::SecretString::new("secret".to_string());
    let _bytes = kapsaro_core::api::secret::SecretBytes::new(vec![1, 2, 3]);
    let _options = kapsaro_core::api::operation::OperationOptions::default();
    let _online = kapsaro_core::api::online::GitHubOnlineVerifier::new(_options);

    assert_eq!(key_store.root(), temp.path().join("keys").as_path());
    assert_eq!(
        trust_store.path(),
        temp.path().join("trust/alice@example.com.json")
    );
}

#[test]
fn key_context_options_group_runtime_inputs() {
    let _options = KeyContextOptions::new(
        "alice@example.com",
        Box::new(StubSshBackend),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA".to_string(),
    )
    .with_kid("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    .with_workspace_path(std::path::PathBuf::from("/tmp/workspace"))
    .with_operation_options(OperationOptions::new().with_debug(true));

    let _load_key_context = LocalKeyStore::load_key_context;
}

#[test]
fn trust_store_exposes_verified_opaque_load_names() {
    let _load_verified = LocalTrustStore::load_verified;

    assert!(std::any::type_name::<TrustApproval>().contains("TrustApproval"));
}

#[test]
fn missing_trust_store_loads_as_none() {
    let temp = tempfile::tempdir().expect("tempdir");
    let key_store = LocalKeyStore::new(temp.path().join("keys"));
    let trust_store = LocalTrustStore::new(temp.path(), "alice@example.com".to_string());

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
    assert!(std::any::type_name::<TrustDecision>().contains("TrustDecision"));
    assert!(std::any::type_name::<TrustPolicyEvaluator>().contains("TrustPolicyEvaluator"));
    assert!(std::any::type_name::<GitHubAccount>().contains("GitHubAccount"));
    assert!(std::any::type_name::<OnlineVerificationResult>().contains("OnlineVerificationResult"));
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
        fn(
            Vec<KvInputEntry>,
            &RecipientKeys,
            &KeyContext,
            OperationOptions,
        ) -> Result<KvEncArtifact>,
    >()
    .contains("fn"));

    let _encrypt_entries = KvEncArtifact::encrypt_entries;
    let _list_entry_keys = KvEncArtifact::list_entry_keys;
    let _decrypt_entry = VerifiedKvEncArtifact::decrypt_entry;
    let _decrypt_entries = VerifiedKvEncArtifact::decrypt_entries;
    let _set_entries = VerifiedKvEncArtifact::set_entries;
    let _unset_entry = VerifiedKvEncArtifact::unset_entry;
}

#[test]
fn artifact_facades_expose_verified_operations() {
    let _verify_file = FileEncArtifact::verify;
    let _verify_kv = KvEncArtifact::verify;
    let _decrypt_file = VerifiedFileEncArtifact::decrypt_bytes;
    let _decrypt_kv_entry = VerifiedKvEncArtifact::decrypt_entry;
    let _decrypt_kv_entries = VerifiedKvEncArtifact::decrypt_entries;
    let _set_kv_entries = VerifiedKvEncArtifact::set_entries;
    let _unset_kv_entry = VerifiedKvEncArtifact::unset_entry;

    assert!(std::any::type_name::<VerifiedFileEncArtifact>().contains("VerifiedFileEncArtifact"));
    assert!(std::any::type_name::<VerifiedKvEncArtifact>().contains("VerifiedKvEncArtifact"));
}

#[test]
fn trust_evaluator_returns_review_without_prompting() {
    let evaluator = TrustPolicyEvaluator::new(None);
    let decision = evaluator
        .evaluate_known_key("alice@example.com", "0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        .expect("decision");

    match decision {
        TrustDecision::ReviewRequired(requests) => {
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].kind(), TrustReviewKind::KnownKey);
            assert_eq!(requests[0].subject_handle(), Some("alice@example.com"));
        }
        TrustDecision::Accepted => panic!("missing trust store should require review"),
    }
}

#[test]
#[cfg(not(feature = "online"))]
fn online_facade_fails_closed_without_online_feature() {
    use kapsaro_core::api::online::GitHubOnlineVerifier;

    let verifier = GitHubOnlineVerifier::new(OperationOptions::default());
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
    let _save_fn: fn(&FileEncArtifact, &std::path::Path) -> Result<()> = |a, p| a.save(p);
    let _as_str_fn: fn(&FileEncArtifact) -> &str = FileEncArtifact::as_str;
    let _encrypt_bytes: fn(
        &[u8],
        &RecipientKeys,
        &KeyContext,
        OperationOptions,
    ) -> Result<FileEncArtifact> = FileEncArtifact::encrypt_bytes;
    // Pin recipient_set_subject on VerifiedFileEncArtifact.
    let _rss: fn(&VerifiedFileEncArtifact) -> Result<RecipientSetSubject> =
        VerifiedFileEncArtifact::recipient_set_subject;
}

#[test]
fn test_kv_artifact_io_methods_pinned() {
    // Pin parse/load/save/as_str on KvEncArtifact.
    let _parse: fn(String) -> Result<KvEncArtifact> = KvEncArtifact::parse;
    let _load: fn(&std::path::Path) -> Result<KvEncArtifact> = |p| KvEncArtifact::load(p);
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
    // Pin list_members/list_kids/load_active_kid/set_active_kid/load_recipient_keys.
    let _list_members: fn(&LocalKeyStore) -> Result<Vec<String>> = LocalKeyStore::list_members;
    let _list_kids: fn(&LocalKeyStore, &str) -> Result<Vec<String>> = LocalKeyStore::list_kids;
    let _load_active_kid: fn(&LocalKeyStore, &str) -> Result<Option<String>> =
        LocalKeyStore::load_active_kid;
    let _set_active_kid: fn(&LocalKeyStore, &str, &str) -> Result<()> =
        LocalKeyStore::set_active_kid;
    // load_recipient_keys is generic; call the monomorphised version via a concrete iterator.
    let temp = tempfile::tempdir().expect("tempdir");
    let ks = LocalKeyStore::new(temp.path().join("keys"));
    let _ = ks.load_recipient_keys(std::iter::empty::<String>(), OperationOptions::default());
}

#[test]
fn test_key_context_public_accessors_pinned() {
    // Pin member_handle/kid/expires_at method shapes on KeyContext.
    let _member_handle: fn(&KeyContext) -> &str = KeyContext::member_handle;
    let _kid: fn(&KeyContext) -> &str = KeyContext::kid;
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
    let _verify_keystore_member: fn(
        &GitHubOnlineVerifier,
        &LocalKeyStore,
        &str,
        Option<&str>,
    ) -> Result<OnlineVerificationResult> = GitHubOnlineVerifier::verify_keystore_member;
    // Pin OnlineVerificationResult accessors.
    let _member_handle: fn(&OnlineVerificationResult) -> &str =
        OnlineVerificationResult::member_handle;
    let _status: fn(&OnlineVerificationResult) -> OnlineVerificationStatus =
        OnlineVerificationResult::status;
    let _message: fn(&OnlineVerificationResult) -> &str = OnlineVerificationResult::message;
    let _fingerprint: fn(&OnlineVerificationResult) -> Option<&str> =
        OnlineVerificationResult::fingerprint;
    let _matched_key_id: fn(&OnlineVerificationResult) -> Option<i64> =
        OnlineVerificationResult::matched_key_id;
    let _github_claim_present: fn(&OnlineVerificationResult) -> bool =
        OnlineVerificationResult::github_claim_present;
    let _verified_account: fn(&OnlineVerificationResult) -> Option<&GitHubAccount> =
        OnlineVerificationResult::verified_account;
    // Pin NotConfigured and Failed variant names.
    let _not_configured = OnlineVerificationStatus::NotConfigured;
    let _failed = OnlineVerificationStatus::Failed;
    assert_ne!(_not_configured, OnlineVerificationStatus::Verified);
    assert_ne!(_failed, OnlineVerificationStatus::Verified);
}

#[test]
fn test_operation_options_methods_pinned() {
    let opts = OperationOptions::new()
        .with_allow_expired_key(true)
        .with_debug(false);
    assert!(opts.allow_expired_key());
    assert!(!opts.debug());
    // Pin method shapes.
    let _with_allow_expired_key: fn(OperationOptions, bool) -> OperationOptions =
        OperationOptions::with_allow_expired_key;
    let _debug_getter: fn(&OperationOptions) -> bool = OperationOptions::debug;
    let _allow_expired_key_getter: fn(&OperationOptions) -> bool =
        OperationOptions::allow_expired_key;
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
    // Pin apply_approvals method shape on LocalTrustStore.
    let _apply_approvals: fn(&LocalTrustStore, Vec<TrustApproval>, &KeyContext) -> Result<()> =
        LocalTrustStore::apply_approvals;
}

#[test]
fn test_trust_evaluator_evaluate_recipient_set_pinned() {
    // Pin evaluate_recipient_set method shape on TrustPolicyEvaluator.
    let _eval: fn(&TrustPolicyEvaluator, &RecipientSetSubject) -> Result<TrustDecision> =
        TrustPolicyEvaluator::evaluate_recipient_set;
}

#[test]
fn test_recipient_set_subject_accessors_pinned() {
    let _sid: fn(&RecipientSetSubject) -> uuid::Uuid = RecipientSetSubject::sid;
    let _recipient_kids: fn(&RecipientSetSubject) -> &[String] =
        RecipientSetSubject::recipient_kids;
}

#[test]
fn test_trust_review_request_accessors_pinned() {
    // Pin kid/sid/recipient_kids accessors on TrustReviewRequest.
    let _kid_fn: fn(&TrustReviewRequest) -> Option<&str> = TrustReviewRequest::kid;
    let _sid_fn: fn(&TrustReviewRequest) -> Option<&str> = TrustReviewRequest::sid;
    let _recipient_kids_fn: fn(&TrustReviewRequest) -> &[String] =
        TrustReviewRequest::recipient_kids;
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
    // Pin known_key/recipient_set constructors.
    let ka = TrustApproval::known_key("alice@example.com", "0123456789ABCDEFGHJKMNPQRSTVWXYZ");
    let sid = uuid::Uuid::new_v4();
    let ra = TrustApproval::recipient_set(sid, vec!["KID1".to_string()]);
    assert!(std::any::type_name::<TrustApproval>().contains("TrustApproval"));
    drop(ka);
    drop(ra);
    // Pin from_request via known-key review path.
    let _from_request: fn(&TrustReviewRequest) -> Result<TrustApproval> =
        TrustApproval::from_request;
}

#[test]
fn test_verified_local_trust_store_load_result_pinned() {
    // Pin VerifiedLocalTrustStoreLoadResult type and its two public methods.
    assert!(std::any::type_name::<VerifiedLocalTrustStoreLoadResult>()
        .contains("VerifiedLocalTrustStoreLoadResult"));
    let _permission_warnings: fn(&VerifiedLocalTrustStoreLoadResult) -> &[String] =
        VerifiedLocalTrustStoreLoadResult::permission_warnings;
    let _into_store: fn(VerifiedLocalTrustStoreLoadResult) -> VerifiedLocalTrustStore =
        VerifiedLocalTrustStoreLoadResult::into_store;
}

#[test]
fn test_error_builder_methods_pinned() {
    // verification_rule accessor.
    let ve = Error::build_verification_error("RULE", "msg");
    assert_eq!(ve.verification_rule(), Some("RULE"));
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
