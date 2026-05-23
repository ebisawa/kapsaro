// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv_core::api::file::{FileEncArtifact, VerifiedFileEncArtifact};
use secretenv_core::api::key::{KeyContext, KeyContextOptions, LocalKeyStore, RecipientKeys};
use secretenv_core::api::kv::{KvEncArtifact, KvInputEntry, VerifiedKvEncArtifact};
use secretenv_core::api::operation::OperationOptions;
use secretenv_core::api::secret::{SecretBytes, SecretString};
use secretenv_core::api::ssh::{SshRawSignature, SshSignatureBackend};
use secretenv_core::api::trust::{
    LocalTrustStore, RecipientSetSubject, TrustApproval, TrustDecision, TrustPolicyEvaluator,
    TrustReviewKind, VerifiedLocalTrustStore,
};
use secretenv_core::{Error, ErrorKind, Result};

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
    let _signature = secretenv_core::api::ssh::SshRawSignature::new([3u8; 64]);
    let _secret = secretenv_core::api::secret::SecretString::new("secret".to_string());
    let _bytes = secretenv_core::api::secret::SecretBytes::new(vec![1, 2, 3]);
    let _options = secretenv_core::api::operation::OperationOptions::default();
    let _online = secretenv_core::api::online::GitHubOnlineVerifier::new(_options);

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
    use secretenv_core::api::online::GitHubOnlineVerifier;

    let verifier = GitHubOnlineVerifier::new(OperationOptions::default());
    let error = verifier
        .resolve_account_by_login("alice")
        .expect_err("online facade must fail without online feature");

    assert_eq!(error.kind(), ErrorKind::Config);
}
