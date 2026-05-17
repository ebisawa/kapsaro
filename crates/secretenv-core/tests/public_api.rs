// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv_core::prelude::*;

use secretenv_core::api::trust::TrustReviewKind;

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
    let home = secretenv_core::api::home::SecretEnvHome::open(temp.path());
    let key_store: secretenv_core::api::key::LocalKeyStore = home.key_store();
    let trust_store: secretenv_core::api::trust::LocalTrustStore =
        home.trust_store("alice@example.com");
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
fn api_does_not_expose_legacy_module_names() {
    let lib_source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("read lib source");
    let api_source =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api/mod.rs"))
            .expect("read api source");

    assert!(!lib_source.contains("pub mod documents"));
    assert!(!lib_source.contains("pub mod document"));
    assert!(!api_source.contains("pub mod artifacts"));
    assert!(!api_source.contains("pub mod keys"));
    assert!(!api_source.contains("pub mod types"));
}

#[test]
fn api_module_paths_are_canonical_without_flat_reexports() {
    let api_source =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api/mod.rs"))
            .expect("read api source");

    assert!(api_source.contains("pub mod file;"));
    assert!(api_source.contains("pub mod key;"));
    assert!(api_source.contains("pub mod kv;"));
    assert!(api_source.contains("pub mod online;"));
    assert!(api_source.contains("pub mod trust;"));
    assert!(!api_source.contains("pub use "));
}

#[test]
fn implementation_module_roots_are_not_public_module_surfaces() {
    for path in [
        "src/app.rs",
        "src/config.rs",
        "src/crypto.rs",
        "src/feature.rs",
        "src/format.rs",
        "src/io.rs",
        "src/model.rs",
        "src/support.rs",
    ] {
        let source = std::fs::read_to_string(format!("{}/{}", env!("CARGO_MANIFEST_DIR"), path))
            .expect("read implementation root");
        let public_module_lines = source
            .lines()
            .filter(|line| line.starts_with("pub mod "))
            .collect::<Vec<_>>();
        assert!(
            public_module_lines.is_empty(),
            "{path} exposes public module roots:\n{}",
            public_module_lines.join("\n")
        );
    }
}

#[test]
fn prelude_does_not_export_document_dtos() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/prelude.rs"))
        .expect("read prelude source");

    assert!(!source.contains("pub use crate::document"));
}

#[test]
fn key_context_options_group_runtime_inputs() {
    let options = KeyContextOptions::new(
        "alice@example.com",
        Box::new(StubSshBackend),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA".to_string(),
    )
    .with_kid("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    .with_workspace_path(std::path::PathBuf::from("/tmp/workspace"))
    .with_operation_options(OperationOptions::new().with_debug(true));

    assert_eq!(options.member_handle(), "alice@example.com");
    assert_eq!(options.kid(), Some("0123456789ABCDEFGHJKMNPQRSTVWXYZ"));
    assert!(options.workspace_path().is_some());
    assert!(options.operation_options().debug());

    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api/key.rs"))
        .expect("read key facade source");
    assert!(!source.contains("pub fn with_debug"));
}

#[test]
fn trust_store_exposes_verified_opaque_load_names() {
    let _load_verified = LocalTrustStore::load_verified;
    let _load_verified_with_warnings = LocalTrustStore::load_verified_with_warnings;

    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api/trust.rs"))
        .expect("read trust facade source");
    assert!(!source.contains("pub fn load_raw"));
    assert!(!source.contains("pub fn load_raw_with_warnings"));
    assert!(!source.contains("pub fn load(&self)"));
    assert!(!source.contains("pub fn load_with_warnings(&self)"));
    assert!(!source.contains("pub fn save_signed"));
    assert!(source.contains("pub struct TrustApproval"));
    assert!(!source.contains("pub struct KnownKeyApproval"));
    assert!(!source.contains("pub struct RecipientSetApproval"));
    assert!(!source.contains("pub enum TrustApprovalKind"));
    assert!(!source.contains("pub document: TrustStoreDocument"));
    assert!(!source.contains("pub fn document(&self) -> &TrustStoreDocument"));
    assert!(!source.contains("pub fn into_document(self) -> TrustStoreDocument"));
    assert!(!source.contains("pub document: TrustStoreDocument"));
    assert!(!source.contains("pub store: VerifiedTrustStore"));
    assert!(!source.contains("pub fn store(&self) -> &VerifiedTrustStore"));
    assert!(!source.contains("pub fn into_store(self) -> VerifiedTrustStore"));
}

#[test]
fn missing_trust_store_loads_as_none() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = SecretEnvHome::open(temp.path());
    let key_store = home.key_store();
    let trust_store = home.trust_store("alice@example.com");

    assert!(trust_store
        .load_verified(&key_store)
        .expect("load missing trust store")
        .is_none());
    assert!(trust_store
        .load_verified_with_warnings(&key_store)
        .expect("load missing trust store with warnings")
        .is_none());
}

#[test]
fn key_store_does_not_expose_raw_key_documents() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api/key.rs"))
        .expect("read key facade source");

    assert!(!source.contains("pub fn load_public_key"));
    assert!(!source.contains("pub fn load_private_key"));
    assert!(!source.contains("pub fn save_key_pair"));
    assert!(!source.contains("pub fn verify("));
    assert!(!source.contains("pub fn keys(&self)"));
    assert!(!source.contains("Result<PublicKey>"));
    assert!(!source.contains("Result<PrivateKey>"));
}

#[test]
fn prelude_exposes_core_facades() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = SecretEnvHome::open(temp.path());
    let key_store = home.key_store();
    let trust_store = home.trust_store("alice@example.com");

    assert_eq!(key_store.root(), temp.path().join("keys").as_path());
    assert_eq!(
        trust_store.path(),
        temp.path().join("trust/alice@example.com.json")
    );
}

#[test]
fn prelude_exposes_facade_helper_types() {
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

    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api/kv.rs"))
        .expect("read kv facade source");
    let secret_source =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api/secret.rs"))
            .expect("read secret facade source");
    let prelude_source =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/prelude.rs"))
            .expect("read prelude source");
    assert!(!source.contains("pub fn new_secret"));
    assert!(!secret_source.contains("pub use crate::support::secret"));
    assert!(!secret_source.contains("pub fn as_str"));
    assert!(!secret_source.contains("pub fn as_bytes"));
    assert!(!secret_source.contains("impl AsRef<str> for SecretString"));
    assert!(!secret_source.contains("impl PartialEq for SecretString"));
    assert!(!secret_source.contains("impl Eq for SecretString"));
    assert!(secret_source.contains("pub struct SecretString"));
    assert!(secret_source.contains("pub struct SecretBytes"));
    assert!(secret_source.contains("pub fn expose_secret(&self) -> &str"));
    assert!(secret_source.contains("pub fn expose_secret(&self) -> &[u8]"));
    assert!(!prelude_source.contains("GitHubAccount"));
    assert!(!prelude_source.contains("GitHubOnlineVerifier"));
    assert!(!prelude_source.contains("OnlineVerificationResult"));
    assert!(!prelude_source.contains("OnlineVerificationStatus"));
    assert!(!prelude_source.contains("TrustReviewKind"));
    assert!(!prelude_source.contains("TrustReviewRequest"));
    assert!(!prelude_source.contains("TrustApproval"));
    assert!(!prelude_source.contains("VerifiedLocalTrustStoreLoadResult"));
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

    let secret_source =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api/secret.rs"))
            .expect("read secret facade source");
    assert!(secret_source.contains("pub fn into_plain_string_for_output(self) -> String"));
    assert!(secret_source.contains("pub fn expose_secret(&self) -> &str"));
    assert!(!secret_source.contains("impl Clone for SecretString"));
    assert!(!secret_source.contains("#[derive(Clone"));
}

#[test]
fn facade_opaque_constructors_and_fields_stay_private() {
    let file_source =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api/file.rs"))
            .expect("read file facade source");
    let kv_source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api/kv.rs"))
        .expect("read kv facade source");
    let trust_source =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api/trust.rs"))
            .expect("read trust facade source");
    let key_source =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api/key.rs"))
            .expect("read key facade source");

    assert!(file_source.contains("pub struct VerifiedFileEncArtifact {\n    inner:"));
    assert!(file_source.contains("pub(crate) fn from_inner"));
    assert!(kv_source.contains("pub struct VerifiedKvEncArtifact {\n    content:"));
    assert!(kv_source.contains("pub(crate) fn from_inner"));
    assert!(key_source.contains("pub struct RecipientKeys {\n    handles:"));
    assert!(key_source.contains("pub(crate) fn keys(&self)"));
    assert!(trust_source.contains("enum TrustApprovalKind"));
    assert!(trust_source.contains("struct KnownKeyApproval"));
    assert!(trust_source.contains("struct RecipientSetApproval"));
    assert!(!trust_source.contains("pub enum TrustApprovalKind"));
    assert!(!trust_source.contains("pub struct KnownKeyApproval"));
    assert!(!trust_source.contains("pub struct RecipientSetApproval"));
}

#[test]
fn error_exposes_stable_kind_for_embedding_apps() {
    let error = Error::build_invalid_argument_error("member handle mismatch");

    assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    assert_eq!(error.format_user_message(), "member handle mismatch");
}

#[test]
fn error_representation_is_opaque() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/error.rs"))
        .expect("read error source");
    let error = Error::build_verification_error("E_PUBLIC_API", "verification failed");

    assert!(!source.contains("pub enum Error {"));
    assert!(source.contains("pub struct Error"));
    assert!(source.contains("enum ErrorRepr"));
    assert_eq!(error.kind(), ErrorKind::Verify);
    assert_eq!(error.verification_rule(), Some("E_PUBLIC_API"));
    assert_eq!(error.format_user_message(), "verification failed");
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

    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api/kv.rs"))
        .expect("read kv facade source");
    assert!(!source.contains("CollectPermissionWarnings"));
    assert!(!source.contains("DocumentStore"));
}

#[test]
fn artifact_facades_verify_to_opaque_artifacts() {
    let _verify_file = FileEncArtifact::verify;
    let _verify_kv = KvEncArtifact::verify;
    let _decrypt_file = VerifiedFileEncArtifact::decrypt_bytes;
    let _decrypt_kv_entry = VerifiedKvEncArtifact::decrypt_entry;
    let _decrypt_kv_entries = VerifiedKvEncArtifact::decrypt_entries;
    let _set_kv_entries = VerifiedKvEncArtifact::set_entries;
    let _unset_kv_entry = VerifiedKvEncArtifact::unset_entry;

    let file_source =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api/file.rs"))
            .expect("read file facade source");
    let kv_source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api/kv.rs"))
        .expect("read kv facade source");
    let file_artifact_impl = file_source
        .split("impl VerifiedFileEncArtifact")
        .next()
        .expect("file artifact impl");
    let kv_artifact_impl = kv_source
        .split("impl VerifiedKvEncArtifact")
        .next()
        .expect("kv artifact impl");

    assert!(!file_source.contains("pub fn from_document"));
    assert!(!file_source.contains("pub fn parse_document"));
    assert!(!file_source.contains("pub fn verify_signature"));
    assert!(!file_source.contains("Result<FileEncDocument>"));
    assert!(!file_source.contains("Result<VerifiedFileEncDocument>"));
    assert!(!file_artifact_impl
        .contains("pub fn recipient_set_subject(&self, options: OperationOptions)"));
    assert!(!file_artifact_impl
        .contains("pub fn decrypt_bytes(\n        &self,\n        member_handle"));
    assert!(!kv_source.contains("pub fn parse_document"));
    assert!(!kv_source.contains("pub fn verify_signature"));
    assert!(!kv_source.contains("Result<KvEncDocument>"));
    assert!(!kv_source.contains("Result<VerifiedKvEncDocument>"));
    assert!(!kv_artifact_impl
        .contains("pub fn recipient_set_subject(&self, options: OperationOptions)"));
    assert!(
        !kv_artifact_impl.contains("pub fn decrypt_entry(\n        &self,\n        member_handle")
    );
    assert!(!kv_artifact_impl
        .contains("pub fn decrypt_entries(\n        &self,\n        member_handle"));
    assert!(file_source
        .contains("pub fn decrypt_bytes(\n        &self,\n        key_ctx: &KeyContext,"));
    assert!(
        kv_source.contains("pub fn decrypt_entry(\n        &self,\n        key_ctx: &KeyContext,")
    );
    assert!(kv_source
        .contains("pub fn decrypt_entries(\n        &self,\n        key_ctx: &KeyContext,"));
    assert!(kv_source.contains("pub fn set_entries(\n        &self,"));
    assert!(kv_source.contains("pub fn unset_entry(\n        &self,"));
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
fn recipient_set_subject_is_built_from_verified_artifact() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api/trust.rs"))
        .expect("read trust facade source");
    let file_source =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api/file.rs"))
            .expect("read file facade source");
    let kv_source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/api/kv.rs"))
        .expect("read kv facade source");

    assert!(file_source.contains("impl VerifiedFileEncArtifact"));
    assert!(file_source.contains("pub fn recipient_set_subject"));
    assert!(kv_source.contains("impl VerifiedKvEncArtifact"));
    assert!(kv_source.contains("pub fn recipient_set_subject"));
    assert!(!file_source.contains("pub fn recipient_set_subject(&self, options: OperationOptions)"));
    assert!(!kv_source.contains("pub fn recipient_set_subject(&self, options: OperationOptions)"));
    assert!(!source.contains("wrap_items: &[WrapItem]"));
    assert!(!source.contains("pub fn from_verified_file"));
    assert!(!source.contains("pub fn from_verified_kv"));
}

#[test]
fn online_feature_connects_to_network_dependencies() {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("read core manifest");

    assert!(manifest.contains("reqwest = {"));
    assert!(manifest.contains("tokio = {"));
    assert!(manifest.contains("optional = true"));
    assert!(manifest.contains("online = [\"dep:reqwest\", \"dep:tokio\"]"));
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
