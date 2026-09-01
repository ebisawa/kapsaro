// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the shared KV read pipeline.
//! Covers the trust re-evaluation gate before decryption.

use std::path::Path;

use kapsaro_core::api::key::{KeyContext, KeyContextOptions, LocalKeyStore, MemberHandle};
use kapsaro_core::api::kv::{KvEncArtifact, KvInputEntry, KvReadOperation, VerifiedKvEncArtifact};
use kapsaro_core::api::operation::OperationOptions;
use kapsaro_core::api::secret::SecretString;
use kapsaro_core::api::ssh::{SshRawSignature, SshSignatureBackend};
use kapsaro_core::api::trust::KnownKeyReview;
use kapsaro_core::api::trust::{CurrentMemberSnapshot, TrustPolicyEvaluator};
use kapsaro_core::cli_api::app::trust::SignerTrustOutcome;
use kapsaro_core::cli_api::test_support::storage::ssh::backend::SignatureBackend;
use kapsaro_core::Result;
use kapsaro_test_support::constants::{ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE};
use kapsaro_test_support::ed25519_backend::Ed25519DirectBackend;
use kapsaro_test_support::fixture::setup_test_workspace_from_fixtures;
use tempfile::TempDir;

use crate::test_utils::EnvGuard;

use super::KvReadReview;

/// Bridge the shared in-process Ed25519 backend to the public signing trait.
///
/// The keystore facade takes a caller-supplied backend while the shared helper
/// implements the internal one, so the two are adapted here rather than
/// spawning ssh-keygen for every fixture key.
struct FixtureSshBackend {
    inner: Ed25519DirectBackend,
}

impl SshSignatureBackend for FixtureSshBackend {
    fn sign_sshsig(
        &self,
        namespace: &str,
        ssh_pubkey: &str,
        message: &[u8],
    ) -> Result<SshRawSignature> {
        self.inner
            .sign_sshsig(namespace, ssh_pubkey, message)
            .map(|signature| SshRawSignature::new(*signature.as_bytes()))
    }
}

fn member_handle(value: &str) -> MemberHandle {
    MemberHandle::try_from(value).expect("valid member handle")
}

fn load_key_context(home: &TempDir, member: &str, workspace: &Path) -> KeyContext {
    let ssh_dir = home.path().join(".ssh");
    let ssh_pubkey = std::fs::read_to_string(ssh_dir.join("test_ed25519.pub"))
        .expect("read fixture ssh public key")
        .trim()
        .to_string();
    let backend = FixtureSshBackend {
        inner: Ed25519DirectBackend::new(&ssh_dir.join("test_ed25519"))
            .expect("load fixture ssh private key"),
    };
    LocalKeyStore::open(home.path().join("keys"))
        .expect("open keystore")
        .load_key_context(
            KeyContextOptions::new(member_handle(member), Box::new(backend), ssh_pubkey)
                .with_workspace_path(workspace),
        )
        .expect("load key context")
}

fn encrypt_kv_artifact(
    home: &TempDir,
    signer_ctx: &KeyContext,
    recipients: &[&str],
    value: &str,
) -> KvEncArtifact {
    let recipient_keys = LocalKeyStore::open(home.path().join("keys"))
        .expect("open keystore")
        .load_recipient_keys(recipients.iter().map(|handle| member_handle(handle)))
        .expect("load recipient keys");
    KvEncArtifact::encrypt_entries(
        vec![KvInputEntry::new(
            "API_KEY",
            SecretString::new(value.to_string()),
        )],
        &recipient_keys,
        signer_ctx,
    )
    .expect("encrypt KV artifact")
}

fn verify(artifact: &KvEncArtifact) -> VerifiedKvEncArtifact {
    artifact
        .verify(OperationOptions::default())
        .expect("verify KV artifact")
}

fn evaluator(workspace: &Path) -> TrustPolicyEvaluator {
    TrustPolicyEvaluator::new(
        CurrentMemberSnapshot::load(workspace).expect("load current members"),
        None,
    )
}

/// A read that clears the trust gate hands back the operation-bound facade, so
/// the decryption acts on the artifact the gate actually answered for.
#[test]
fn test_authorize_returns_the_trusted_artifact_for_an_approved_read() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::remove_var("KAPSARO_STRICT_KEY_CHECKING");
    let (home, workspace) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let key_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE, &workspace);
    let artifact = encrypt_kv_artifact(&home, &key_ctx, &[ALICE_MEMBER_HANDLE], "approved");
    let signer_outcome = SignerTrustOutcome::Accepted;
    let reviewed = verify(&artifact);
    let review = KvReadReview {
        evaluator: evaluator(&workspace),
        reviewed: &reviewed,
        current: verify(&artifact),
        key_ctx: &key_ctx,
        signer_outcome: &signer_outcome,
        known_key_review: KnownKeyReview::Required,
        options: OperationOptions::default(),
    };

    let trusted = review
        .authorize(KvReadOperation::Entries)
        .expect("an approved read must be authorized");

    let entries = trusted.decrypt_entries().expect("decrypt entries");
    assert_eq!(
        entries.get("API_KEY").map(SecretString::expose_secret),
        Some("approved")
    );
}

/// The trust state is resolved again after the review, and a state that no
/// longer approves the artifact has to stop the read rather than fall through
/// to decryption. The command is what re-runs the review, so the pipeline
/// reports the change instead of prompting from inside the read.
#[test]
fn test_authorize_reports_a_trust_state_that_no_longer_approves_the_read() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::remove_var("KAPSARO_STRICT_KEY_CHECKING");
    let (home, workspace) =
        setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE]);
    let key_ctx = load_key_context(&home, ALICE_MEMBER_HANDLE, &workspace);
    let artifact = encrypt_kv_artifact(
        &home,
        &key_ctx,
        &[ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE],
        "pending",
    );
    let signer_outcome = SignerTrustOutcome::Accepted;
    let reviewed = verify(&artifact);
    let review = KvReadReview {
        evaluator: evaluator(&workspace),
        reviewed: &reviewed,
        current: verify(&artifact),
        key_ctx: &key_ctx,
        signer_outcome: &signer_outcome,
        known_key_review: KnownKeyReview::Required,
        options: OperationOptions::default(),
    };

    let Err(error) = review.authorize(KvReadOperation::Entries) else {
        panic!("an unapproved recipient key must stop the read");
    };

    assert_eq!(error.rule(), Some("E_TRUST_REVIEW_REQUIRED"));
    assert!(
        error
            .format_user_message()
            .contains("Trust state changed while reviewing the KV artifact"),
        "the message must name the review the read depended on: {}",
        error.format_user_message()
    );
}
