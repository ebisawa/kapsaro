// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public API tests for local trust store mutation safety.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use secretenv_core::api::key::{KeyContext, KeyContextOptions, LocalKeyStore};
use secretenv_core::api::ssh::{SshRawSignature, SshSignatureBackend};
use secretenv_core::api::trust::TrustApproval;
use secretenv_core::cli_api::test_support::helpers::fs::lock::with_file_lock;
use secretenv_core::cli_api::test_support::storage::ssh::backend::SignatureBackend;
use secretenv_core::ErrorKind;
use tempfile::TempDir;

use crate::test_utils::{
    ed25519_backend::Ed25519DirectBackend, setup_test_workspace_from_fixtures,
    update_active_private_key_expires_at,
};

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";

struct PublicApiSshBackend {
    inner: Ed25519DirectBackend,
}

impl PublicApiSshBackend {
    fn new(path: PathBuf) -> Self {
        Self {
            inner: Ed25519DirectBackend::new(&path).expect("load test SSH key"),
        }
    }
}

impl SshSignatureBackend for PublicApiSshBackend {
    fn sign_sshsig(
        &self,
        namespace: &str,
        ssh_pubkey: &str,
        message: &[u8],
    ) -> secretenv_core::Result<SshRawSignature> {
        let signature = self.inner.sign_sshsig(namespace, ssh_pubkey, message)?;
        Ok(SshRawSignature::new(*signature.as_bytes()))
    }
}

fn load_key_context_from_home_path(home_path: &Path, member_handle: &str) -> KeyContext {
    let key_store = LocalKeyStore::new(home_path.join("keys"));
    load_key_context_from_key_store(home_path, &key_store, member_handle)
}

fn load_key_context_from_key_store(
    home_path: &Path,
    key_store: &LocalKeyStore,
    member_handle: &str,
) -> KeyContext {
    let ssh_private_key = home_path.join(".ssh/test_ed25519");
    let ssh_public_key = fs::read_to_string(home_path.join(".ssh/test_ed25519.pub"))
        .expect("read test SSH public key")
        .trim()
        .to_string();
    let options = KeyContextOptions::new(
        member_handle,
        Box::new(PublicApiSshBackend::new(ssh_private_key)),
        ssh_public_key,
    )
    .with_workspace_path(home_path.join("workspace"));

    key_store
        .load_key_context(options)
        .expect("load key context")
}

fn load_key_context(temp: &TempDir, member_handle: &str) -> KeyContext {
    load_key_context_from_home_path(temp.path(), member_handle)
}

fn build_trust_store(
    home_path: &Path,
    owner_handle: &str,
) -> secretenv_core::api::trust::LocalTrustStore {
    secretenv_core::api::trust::LocalTrustStore::new(home_path, owner_handle.to_string())
}

fn fixture_kid(key_store: &LocalKeyStore, member_handle: &str) -> String {
    key_store
        .list_kids(member_handle)
        .expect("list member kids")
        .into_iter()
        .next()
        .expect("member kid must exist")
}

fn tamper_first_known_key_subject(path: &Path, subject_handle: &str) {
    let mut value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(path).expect("read trust store"))
            .expect("parse trust store");
    value["protected"]["known_keys"][0]["subject_handle"] =
        serde_json::Value::String(subject_handle.to_string());
    fs::write(
        path,
        serde_json::to_string_pretty(&value).expect("serialize trust store"),
    )
    .expect("write tampered trust store");
}

#[test]
fn apply_approvals_revalidates_existing_store_with_key_context_keystore() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let default_keys = temp.path().join("keys");
    let custom_keys = temp.path().join("custom_keys");
    fs::rename(&default_keys, &custom_keys).expect("move fixture keys outside default location");
    let key_store = LocalKeyStore::new(&custom_keys);
    let trust_store = build_trust_store(temp.path(), ALICE);
    let alice_key_ctx = load_key_context_from_key_store(temp.path(), &key_store, ALICE);
    let bob_kid = fixture_kid(&key_store, BOB);

    trust_store
        .apply_approvals(
            vec![TrustApproval::known_key(BOB, bob_kid.clone())],
            &alice_key_ctx,
        )
        .expect("create trust store with explicit keystore");
    trust_store
        .apply_approvals(
            vec![TrustApproval::recipient_set(
                uuid::Uuid::new_v4(),
                vec![bob_kid],
            )],
            &alice_key_ctx,
        )
        .expect("revalidate existing trust store with explicit keystore");

    assert!(
        trust_store
            .load_verified(&key_store)
            .expect("load trust store with explicit keystore")
            .is_some(),
        "trust store must verify with the caller-supplied keystore"
    );
}

#[test]
fn apply_approvals_rejects_invalid_existing_trust_store() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let key_store = LocalKeyStore::new(temp.path().join("keys"));
    let trust_store = build_trust_store(temp.path(), ALICE);
    let alice_key_ctx = load_key_context(&temp, ALICE);
    let bob_kid = fixture_kid(&key_store, BOB);

    trust_store
        .apply_approvals(
            vec![TrustApproval::known_key(BOB, bob_kid.clone())],
            &alice_key_ctx,
        )
        .expect("create valid trust store");
    tamper_first_known_key_subject(&trust_store.path(), "mallory@example.com");

    let err = trust_store
        .apply_approvals(
            vec![TrustApproval::recipient_set(
                uuid::Uuid::new_v4(),
                vec![bob_kid],
            )],
            &alice_key_ctx,
        )
        .expect_err("invalid existing trust store must not be re-signed");

    assert!(
        err.format_user_message()
            .contains("Trust store signature verification failed"),
        "unexpected error: {}",
        err.format_user_message()
    );
    assert!(
        trust_store.load_verified(&key_store).is_err(),
        "tampered trust store must remain invalid"
    );
}

#[test]
fn apply_approvals_rejects_key_context_for_different_owner() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let key_store = LocalKeyStore::new(temp.path().join("keys"));
    let trust_store = build_trust_store(temp.path(), ALICE);
    let bob_key_ctx = load_key_context(&temp, BOB);
    let bob_kid = fixture_kid(&key_store, BOB);

    let err = trust_store
        .apply_approvals(vec![TrustApproval::known_key(BOB, bob_kid)], &bob_key_ctx)
        .expect_err("mismatched key context must be rejected");

    assert_eq!(err.kind(), ErrorKind::InvalidArgument);
    assert!(
        !trust_store.path().exists(),
        "mismatched key context must not create a trust store"
    );
}

#[test]
fn apply_approvals_rejects_malformed_known_key_kid() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let trust_store = build_trust_store(temp.path(), ALICE);
    let alice_key_ctx = load_key_context(&temp, ALICE);

    let err = trust_store
        .apply_approvals(
            vec![TrustApproval::known_key(BOB, "not-a-canonical-kid")],
            &alice_key_ctx,
        )
        .expect_err("malformed known-key kid must be rejected");

    assert_eq!(err.kind(), ErrorKind::InvalidArgument);
    assert!(
        !trust_store.path().exists(),
        "malformed known-key kid must not create a trust store"
    );
}

#[test]
fn apply_approvals_rejects_malformed_known_key_subject_handle() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let key_store = LocalKeyStore::new(temp.path().join("keys"));
    let trust_store = build_trust_store(temp.path(), ALICE);
    let alice_key_ctx = load_key_context(&temp, ALICE);
    let bob_kid = fixture_kid(&key_store, BOB);

    let err = trust_store
        .apply_approvals(
            vec![TrustApproval::known_key("../bob", bob_kid)],
            &alice_key_ctx,
        )
        .expect_err("malformed known-key subject handle must be rejected");

    assert_eq!(err.kind(), ErrorKind::InvalidArgument);
    assert!(
        !trust_store.path().exists(),
        "malformed known-key subject handle must not create a trust store"
    );
}

#[test]
fn apply_approvals_rejects_expired_signing_key() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    update_active_private_key_expires_at(temp.path(), ALICE, "2020-01-01T00:00:00Z");
    let key_store = LocalKeyStore::new(temp.path().join("keys"));
    let trust_store = build_trust_store(temp.path(), ALICE);
    let expired_key_ctx = load_key_context(&temp, ALICE);
    let bob_kid = fixture_kid(&key_store, BOB);

    let err = trust_store
        .apply_approvals(
            vec![TrustApproval::known_key(BOB, bob_kid)],
            &expired_key_ctx,
        )
        .expect_err("expired signing key must be rejected");

    assert_eq!(err.kind(), ErrorKind::Verify);
    assert!(
        err.format_user_message().contains("Local key has expired"),
        "unexpected error: {}",
        err.format_user_message()
    );
    assert!(
        !trust_store.path().exists(),
        "expired signing key must not create a trust store"
    );
}

#[test]
fn apply_approvals_waits_for_trust_store_file_lock() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let key_store = LocalKeyStore::new(temp.path().join("keys"));
    let trust_store = build_trust_store(temp.path(), ALICE);
    let path = trust_store.path();
    let home_path = temp.path().to_path_buf();
    let bob_kid = fixture_kid(&key_store, BOB);
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();

    let worker = with_file_lock(&path, || {
        let worker = thread::spawn(move || {
            let trust_store = build_trust_store(&home_path, ALICE);
            let key_ctx = load_key_context_from_home_path(&home_path, ALICE);
            ready_tx.send(()).expect("signal worker ready");
            let result = trust_store
                .apply_approvals(vec![TrustApproval::known_key(BOB, bob_kid)], &key_ctx)
                .map_err(|err| err.format_user_message().to_string());
            done_tx.send(result).expect("signal worker done");
        });

        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("worker must reach apply_approvals");
        assert!(
            done_rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "apply_approvals must wait for the trust store file lock"
        );
        Ok::<_, secretenv_core::Error>(worker)
    })
    .expect("hold trust store lock");

    let result = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("worker must complete after lock release");
    worker.join().expect("worker thread must not panic");
    result.expect("apply_approvals must succeed after lock release");
    assert!(
        trust_store.load_verified(&key_store).is_ok(),
        "trust store must remain valid after locked mutation"
    );
}
