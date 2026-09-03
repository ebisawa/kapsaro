// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public API tests for local trust store mutation safety.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Barrier};
use std::thread;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::{symlink, PermissionsExt};

use crate::feature::trust::recipient_sets::compute_recipient_set_hash;
use crate::feature::trust::signature::sign_trust_store;
use crate::io::ssh::backend::SignatureBackend;
use crate::io::trust::paths::{get_trust_store_dir, get_trust_store_file_path};
use crate::io::trust::store::fail_next_trust_store_save;
use crate::model::trust_store::{RecipientSetApprovalVia, RecipientSetRecord, TrustStoreProtected};
use crate::model::wire::format::LOCAL_TRUST_V1;
use crate::support::fs::lock::lock_test_support::with_locked_workspace_dir;
#[cfg(unix)]
use crate::support::warning::LocalStateWarningGuard;
use crate::test_support::storage::trust::store::save_trust_store;
use crate::test_utils::{create_local_state_dir, member_handle, setup_member_key_context};
use kapsaro_core::api::key::{KeyContext, KeyContextOptions, LocalKeyStore, MemberHandle};
use kapsaro_core::api::ssh::{SshRawSignature, SshSignatureBackend};
use kapsaro_core::api::trust::{ApprovalConflictHandling, TrustApproval};
use kapsaro_core::ErrorKind;
use serde_json::Value;
use tempfile::TempDir;

use crate::app_test_utils::{rotate_active_key, save_test_trust_store_signed_by_active_key};
use crate::test_utils::{
    ed25519_backend::Ed25519DirectBackend, setup_test_workspace_from_fixtures,
    update_active_private_key_expires_at,
};

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
/// Recipient named by the seed approval, unrelated to any fixture member.
const SEED_RECIPIENT_KID: &str = "5EED00005EED00005EED00005EED0000";
/// Timestamp a directly written trust store carries, distinct from any run time.
const STORED_AT: &str = "2026-03-29T12:34:56Z";
/// Staging suffix of a write still holding the trust directory's lock.
const LIVE_WRITER_STAGING_UUID: &str = "6f1c3a4e-9b2d-4c7a-8e51-0d3f27a6b418";
/// Staging suffix an interrupted write left behind with no lock holder.
const STALE_WRITER_STAGING_UUID: &str = "b47d81f0-3c62-4a95-9d18-52e7c0af6d23";

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
    ) -> kapsaro_core::Result<SshRawSignature> {
        let signature = self.inner.sign_sshsig(namespace, ssh_pubkey, message)?;
        Ok(SshRawSignature::new(*signature.as_bytes()))
    }
}

fn load_key_context_from_home_path(home_path: &Path, member_handle: &str) -> KeyContext {
    let key_store = LocalKeyStore::open(home_path.join("keys")).expect("open keystore");
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
        member(member_handle),
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
) -> kapsaro_core::api::trust::LocalTrustStore {
    kapsaro_core::api::trust::LocalTrustStore::open(home_path, member(owner_handle))
        .expect("open trust store")
}

fn member(value: &str) -> MemberHandle {
    MemberHandle::try_from(value).expect("valid member handle")
}

fn fixture_kid(key_store: &LocalKeyStore, member_handle: &str) -> String {
    key_store
        .list_kids(&member(member_handle))
        .expect("list member kids")
        .into_iter()
        .map(|kid| kid.into_string())
        .next()
        .expect("member kid must exist")
}

/// Write a stored trust store the rest of the test can read back.
///
/// The seed approves a recipient set rather than a known key: it moves the
/// content enough to create the file while leaving `known_keys` empty for the
/// tests that count what they approved themselves.
fn seed_trust_store(trust_store: &kapsaro_core::api::trust::LocalTrustStore, key_ctx: &KeyContext) {
    trust_store
        .apply_approvals_with_conflict_handling(
            vec![TrustApproval::recipient_set_for_test(
                uuid::Uuid::new_v4(),
                vec![SEED_RECIPIENT_KID.to_string()],
            )],
            key_ctx,
            ApprovalConflictHandling::merge(),
        )
        .expect("seed trust store");
}

fn read_stored_trust_store(trust_store: &kapsaro_core::api::trust::LocalTrustStore) -> Value {
    serde_json::from_slice(&fs::read(trust_store.path()).expect("read stored trust store"))
        .expect("parse stored trust store")
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
    let key_store = LocalKeyStore::open(&custom_keys).expect("open custom keystore");
    let trust_store = build_trust_store(temp.path(), ALICE);
    let alice_key_ctx = load_key_context_from_key_store(temp.path(), &key_store, ALICE);
    let bob_kid = fixture_kid(&key_store, BOB);

    trust_store
        .apply_approvals_with_conflict_handling(
            vec![TrustApproval::known_key_for_test(BOB, bob_kid.clone())],
            &alice_key_ctx,
            ApprovalConflictHandling::merge(),
        )
        .expect("create trust store with explicit keystore");
    trust_store
        .apply_approvals_with_conflict_handling(
            vec![TrustApproval::recipient_set_for_test(
                uuid::Uuid::new_v4(),
                vec![bob_kid],
            )],
            &alice_key_ctx,
            ApprovalConflictHandling::merge(),
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
    let key_store = LocalKeyStore::open(temp.path().join("keys")).expect("open keystore");
    let trust_store = build_trust_store(temp.path(), ALICE);
    let alice_key_ctx = load_key_context(&temp, ALICE);
    let bob_kid = fixture_kid(&key_store, BOB);

    trust_store
        .apply_approvals_with_conflict_handling(
            vec![TrustApproval::known_key_for_test(BOB, bob_kid.clone())],
            &alice_key_ctx,
            ApprovalConflictHandling::merge(),
        )
        .expect("create valid trust store");
    tamper_first_known_key_subject(&trust_store.path(), "mallory@example.com");

    let err = trust_store
        .apply_approvals_with_conflict_handling(
            vec![TrustApproval::recipient_set_for_test(
                uuid::Uuid::new_v4(),
                vec![bob_kid],
            )],
            &alice_key_ctx,
            ApprovalConflictHandling::merge(),
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
    let key_store = LocalKeyStore::open(temp.path().join("keys")).expect("open keystore");
    let trust_store = build_trust_store(temp.path(), ALICE);
    let bob_key_ctx = load_key_context(&temp, BOB);
    let bob_kid = fixture_kid(&key_store, BOB);

    let err = trust_store
        .apply_approvals_with_conflict_handling(
            vec![TrustApproval::known_key_for_test(BOB, bob_kid)],
            &bob_key_ctx,
            ApprovalConflictHandling::merge(),
        )
        .expect_err("mismatched key context must be rejected");

    assert_eq!(err.kind(), ErrorKind::InvalidArgument);
    assert!(
        !trust_store.path().exists(),
        "mismatched key context must not create a trust store"
    );
}

#[test]
fn apply_approvals_rejects_expired_signing_key() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    update_active_private_key_expires_at(temp.path(), ALICE, "2020-01-01T00:00:00Z");
    let key_store = LocalKeyStore::open(temp.path().join("keys")).expect("open keystore");
    let trust_store = build_trust_store(temp.path(), ALICE);
    let expired_key_ctx = load_key_context(&temp, ALICE);
    let bob_kid = fixture_kid(&key_store, BOB);

    let err = trust_store
        .apply_approvals_with_conflict_handling(
            vec![TrustApproval::known_key_for_test(BOB, bob_kid)],
            &expired_key_ctx,
            ApprovalConflictHandling::merge(),
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
fn test_apply_approvals_waits_for_trust_store_dir_lock() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let key_store = LocalKeyStore::open(temp.path().join("keys")).expect("open keystore");
    let trust_store = build_trust_store(temp.path(), ALICE);
    let trust_dir = get_trust_store_dir(temp.path());
    create_local_state_dir(&trust_dir);
    let home_path = temp.path().to_path_buf();
    let bob_kid = fixture_kid(&key_store, BOB);
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();

    let worker = with_locked_workspace_dir(&trust_dir, |_| {
        let worker = thread::spawn(move || {
            let trust_store = build_trust_store(&home_path, ALICE);
            let key_ctx = load_key_context_from_home_path(&home_path, ALICE);
            ready_tx.send(()).expect("signal worker ready");
            let result = trust_store
                .apply_approvals_with_conflict_handling(
                    vec![TrustApproval::known_key_for_test(BOB, bob_kid)],
                    &key_ctx,
                    ApprovalConflictHandling::merge(),
                )
                .map_err(|err| err.format_user_message().to_string());
            done_tx.send(result).expect("signal worker done");
        });

        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("worker must reach apply_approvals");
        assert!(
            done_rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "apply_approvals must wait for the trust store directory lock"
        );
        Ok::<_, kapsaro_core::Error>(worker)
    })
    .expect("hold trust store directory lock");

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

#[test]
fn apply_approvals_with_no_effect_leaves_the_stored_bytes_alone() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let key_store = LocalKeyStore::open(temp.path().join("keys")).expect("open keystore");
    let trust_store = build_trust_store(temp.path(), ALICE);
    let key_ctx = load_key_context(&temp, ALICE);
    let bob_kid = fixture_kid(&key_store, BOB);
    let first = trust_store
        .apply_approvals_with_conflict_handling(
            vec![TrustApproval::known_key_for_test(BOB, bob_kid.clone())],
            &key_ctx,
            ApprovalConflictHandling::merge(),
        )
        .expect("approve bob for the first time");
    assert_eq!(first.applied(), 1);
    assert!(first.warnings().diagnostics().is_empty());
    let stored = fs::read(trust_store.path()).expect("read stored trust store");
    // Any save this call attempts fails here, so completing it proves the
    // approval the store already holds reached the file system at all.
    fail_next_trust_store_save();

    let duplicate = trust_store
        .apply_approvals_with_conflict_handling(
            vec![TrustApproval::known_key_for_test(BOB, bob_kid)],
            &key_ctx,
            ApprovalConflictHandling::merge(),
        )
        .expect("re-apply the approval the store already holds");

    assert_eq!(duplicate.applied(), 0);
    assert!(duplicate.warnings().diagnostics().is_empty());
    assert_eq!(fs::read(trust_store.path()).unwrap(), stored);
}

#[cfg(unix)]
#[test]
fn apply_approvals_returns_operation_permission_warnings_without_leaking_them() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let key_store = LocalKeyStore::open(temp.path().join("keys")).expect("open keystore");
    let trust_store = build_trust_store(temp.path(), ALICE);
    let key_ctx = load_key_context(&temp, ALICE);
    let bob_kid = fixture_kid(&key_store, BOB);
    seed_trust_store(&trust_store, &key_ctx);
    let trust_dir = trust_store.path().parent().unwrap().to_path_buf();
    fs::set_permissions(&trust_dir, fs::Permissions::from_mode(0o755))
        .expect("make trust directory observable by other users");
    let warning_guard = LocalStateWarningGuard::new();

    let outcome = trust_store
        .apply_approvals_with_conflict_handling(
            vec![TrustApproval::known_key_for_test(BOB, bob_kid)],
            &key_ctx,
            ApprovalConflictHandling::merge(),
        )
        .expect("permission warnings must remain non-fatal");

    assert!(outcome
        .warnings()
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.path() == trust_dir));
    assert!(warning_guard.take().warnings.is_empty());
}

/// Write a trust store that already approves one recipient set.
///
/// Every stored timestamp is `STORED_AT`, so a later approval that moves
/// `updated_at` is visible whatever time the test itself runs at.
fn seed_trust_store_with_recipient_set(
    home: &TempDir,
    owner_handle: &str,
    sid: uuid::Uuid,
    recipient_kids: Vec<String>,
) {
    let key_ctx = setup_member_key_context(home, owner_handle, None);
    let record = RecipientSetRecord {
        sid: sid.to_string(),
        recipient_set_hash: compute_recipient_set_hash(&recipient_kids)
            .expect("compute recipient set hash"),
        recipient_kids,
        approved_at: STORED_AT.to_string(),
        approved_via: RecipientSetApprovalVia::ManualReview,
        recipient_handle_hints: None,
    };
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: owner_handle.to_string(),
        created_at: STORED_AT.to_string(),
        updated_at: STORED_AT.to_string(),
        known_keys: Vec::new(),
        recipient_sets: vec![record],
    };
    let document = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid())
        .expect("sign seeded trust store");
    save_trust_store(
        &get_trust_store_file_path(home.path(), &member_handle(owner_handle)),
        &document,
    )
    .expect("save seeded trust store");
}

#[test]
fn reapproving_the_same_recipient_set_moves_the_approval_forward() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let key_store = LocalKeyStore::open(temp.path().join("keys")).expect("open keystore");
    let bob_kid = fixture_kid(&key_store, BOB);
    let sid = uuid::Uuid::new_v4();
    seed_trust_store_with_recipient_set(&temp, ALICE, sid, vec![bob_kid.clone()]);
    let trust_store = build_trust_store(temp.path(), ALICE);
    let key_ctx = load_key_context(&temp, ALICE);

    trust_store
        .apply_approvals_with_conflict_handling(
            vec![TrustApproval::recipient_set_for_test(sid, vec![bob_kid])],
            &key_ctx,
            ApprovalConflictHandling::merge(),
        )
        .expect("re-approve the recipient set the store already holds");

    let stored = read_stored_trust_store(&trust_store);
    assert_ne!(
        stored["protected"]["recipient_sets"][0]["approved_at"],
        STORED_AT
    );
    assert_ne!(stored["protected"]["updated_at"], STORED_AT);
}

#[test]
fn approving_a_changed_recipient_set_moves_updated_at() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let key_store = LocalKeyStore::open(temp.path().join("keys")).expect("open keystore");
    let bob_kid = fixture_kid(&key_store, BOB);
    let sid = uuid::Uuid::new_v4();
    seed_trust_store_with_recipient_set(&temp, ALICE, sid, vec![bob_kid.clone()]);
    let trust_store = build_trust_store(temp.path(), ALICE);
    let key_ctx = load_key_context(&temp, ALICE);

    trust_store
        .apply_approvals_with_conflict_handling(
            vec![TrustApproval::recipient_set_for_test(
                sid,
                vec![bob_kid, SEED_RECIPIENT_KID.to_string()],
            )],
            &key_ctx,
            ApprovalConflictHandling::merge(),
        )
        .expect("approve the recipient set the artifact now names");

    let stored = read_stored_trust_store(&trust_store);
    assert_ne!(stored["protected"]["updated_at"], STORED_AT);
    assert_eq!(
        stored["protected"]["recipient_sets"][0]["recipient_kids"]
            .as_array()
            .expect("stored recipient kids")
            .len(),
        2
    );
}

#[test]
fn apply_approvals_resigns_for_a_rotated_key_without_touching_updated_at() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE]);
    save_test_trust_store_signed_by_active_key(&temp, ALICE, STORED_AT);
    let trust_store = build_trust_store(temp.path(), ALICE);
    let rotated_kid = rotate_active_key(temp.path(), ALICE);
    let rotated_key_ctx = load_key_context(&temp, ALICE);

    trust_store
        .apply_approvals_with_conflict_handling(
            Vec::new(),
            &rotated_key_ctx,
            ApprovalConflictHandling::merge(),
        )
        .expect("hand the stored signature to the rotated key");

    let stored = read_stored_trust_store(&trust_store);
    assert_eq!(stored["signature"]["kid"], rotated_kid.as_str());
    assert_eq!(stored["protected"]["updated_at"], STORED_AT);
}

/// The gate binds to the exact bytes that were reviewed, so a rewrite that
/// leaves the same document behind still stops the approval: nothing read the
/// replacement, and it may not be the document it parses as.
#[test]
fn test_apply_approvals_rejects_a_byte_level_change_to_reviewed_content() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let key_store = LocalKeyStore::open(temp.path().join("keys")).expect("open keystore");
    let trust_store = build_trust_store(temp.path(), ALICE);
    let key_ctx = load_key_context(&temp, ALICE);
    seed_trust_store(&trust_store, &key_ctx);
    let bob_kid = fixture_kid(&key_store, BOB);
    let reviewed = trust_store
        .load_verified(&key_store)
        .expect("load the trust store the approval is decided on")
        .expect("seeded trust store exists");
    let path = trust_store.path();
    let mut replacement = fs::read(&path).expect("read trust store snapshot");
    replacement.push(b'\n');
    fs::write(&path, &replacement).expect("replace trust store after the review");

    let error = trust_store
        .apply_approvals_with_conflict_handling(
            vec![TrustApproval::known_key_for_test(BOB, bob_kid)],
            &key_ctx,
            ApprovalConflictHandling::surface(&reviewed),
        )
        .expect_err("changed trust store snapshot must stop commit");

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert_eq!(fs::read(&path).unwrap(), replacement);
}

/// `load_verified` answers "there is no store" with `None`, and a caller that
/// approved on the strength of that answer binds the write to that absence.
#[test]
fn test_apply_approvals_surfaces_a_reviewed_absence() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let key_store = LocalKeyStore::open(temp.path().join("keys")).expect("open keystore");
    let trust_store = build_trust_store(temp.path(), ALICE);
    let key_ctx = load_key_context(&temp, ALICE);
    let bob_kid = fixture_kid(&key_store, BOB);
    assert!(trust_store.load_verified(&key_store).unwrap().is_none());

    trust_store
        .apply_approvals_with_conflict_handling(
            vec![TrustApproval::known_key_for_test(BOB, bob_kid.clone())],
            &key_ctx,
            ApprovalConflictHandling::surface_absent(),
        )
        .expect("an approval bound to a reviewed absence creates the store");

    let loaded = trust_store.load_verified(&key_store).unwrap().unwrap();
    assert!(loaded
        .protected()
        .known_keys
        .iter()
        .any(|entry| entry.kid == bob_kid));
}

/// A store that appeared after the caller was told there was none is content it
/// never saw, so the approval stops rather than landing on top of it.
#[test]
fn test_apply_approvals_surfacing_an_absence_rejects_a_store_that_appeared() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let key_store = LocalKeyStore::open(temp.path().join("keys")).expect("open keystore");
    let trust_store = build_trust_store(temp.path(), ALICE);
    let key_ctx = load_key_context(&temp, ALICE);
    let bob_kid = fixture_kid(&key_store, BOB);
    seed_trust_store(&trust_store, &key_ctx);

    let error = trust_store
        .apply_approvals_with_conflict_handling(
            vec![TrustApproval::known_key_for_test(BOB, bob_kid.clone())],
            &key_ctx,
            ApprovalConflictHandling::surface_absent(),
        )
        .expect_err("a store that appeared since the review must stop the approval");

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    let loaded = trust_store.load_verified(&key_store).unwrap().unwrap();
    assert!(loaded
        .protected()
        .known_keys
        .iter()
        .all(|entry| entry.kid != bob_kid));
}

#[test]
fn test_apply_approvals_surfaces_change_to_public_reviewed_snapshot() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let trust_store = build_trust_store(temp.path(), ALICE);
    let key_ctx = load_key_context(&temp, ALICE);
    let key_store = LocalKeyStore::open(temp.path().join("keys")).expect("open keystore");
    seed_trust_store(&trust_store, &key_ctx);
    let reviewed = trust_store
        .load_verified(&key_store)
        .unwrap()
        .expect("reviewed trust store exists");
    let concurrent_kid = "C4A00000C4A00000C4A00000C4A00000";
    trust_store
        .apply_approvals_with_conflict_handling(
            vec![TrustApproval::known_key_for_test(
                "charlie@example.com",
                concurrent_kid,
            )],
            &key_ctx,
            ApprovalConflictHandling::merge(),
        )
        .unwrap();
    let bob_kid = fixture_kid(&key_store, BOB);

    let error = trust_store
        .apply_approvals_with_conflict_handling(
            vec![TrustApproval::known_key_for_test(BOB, bob_kid.clone())],
            &key_ctx,
            ApprovalConflictHandling::surface(&reviewed),
        )
        .expect_err("approval must stay bound to reviewed trust content");

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    let loaded = trust_store.load_verified(&key_store).unwrap().unwrap();
    assert!(loaded
        .protected()
        .known_keys
        .iter()
        .any(|entry| entry.kid == concurrent_kid));
    assert!(loaded
        .protected()
        .known_keys
        .iter()
        .all(|entry| entry.kid != bob_kid));
}

#[test]
fn test_apply_approvals_preserves_both_concurrent_known_keys() {
    const CHARLIE_KID: &str = "C4A00000C4A00000C4A00000C4A00000";

    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE, BOB]);
    let trust_store = build_trust_store(temp.path(), ALICE);
    let key_ctx = load_key_context(&temp, ALICE);
    let key_store = LocalKeyStore::open(temp.path().join("keys")).expect("open keystore");
    let bob_kid = fixture_kid(&key_store, BOB);
    seed_trust_store(&trust_store, &key_ctx);
    let home = temp.path().to_path_buf();
    let start = Arc::new(Barrier::new(2));
    let writers = [
        (BOB.to_string(), bob_kid.clone()),
        ("charlie@example.com".to_string(), CHARLIE_KID.to_string()),
    ]
    .into_iter()
    .map(|(member_handle, kid)| {
        let home = home.clone();
        let start = Arc::clone(&start);
        thread::spawn(move || {
            let trust_store = build_trust_store(&home, ALICE);
            let key_ctx = load_key_context_from_home_path(&home, ALICE);
            start.wait();
            trust_store.apply_approvals_with_conflict_handling(
                vec![TrustApproval::known_key_for_test(member_handle, kid)],
                &key_ctx,
                ApprovalConflictHandling::merge(),
            )
        })
    })
    .collect::<Vec<_>>();
    for writer in writers {
        writer.join().unwrap().unwrap();
    }
    let loaded = trust_store
        .load_verified(&key_store)
        .expect("load verified trust store")
        .expect("trust store exists");
    assert!(loaded
        .protected()
        .known_keys
        .iter()
        .any(|entry| entry.kid == bob_kid));
    assert!(loaded
        .protected()
        .known_keys
        .iter()
        .any(|entry| entry.kid == CHARLIE_KID));
}

#[test]
fn test_apply_approvals_concurrent_writers_all_converge() {
    const WRITER_COUNT: usize = 5;

    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE]);
    let home = temp.path().to_path_buf();
    let trust_store = build_trust_store(&home, ALICE);
    let key_ctx = load_key_context(&temp, ALICE);
    seed_trust_store(&trust_store, &key_ctx);
    let start = Arc::new(Barrier::new(WRITER_COUNT));

    let workers = (0..WRITER_COUNT)
        .map(|writer| {
            let home = home.clone();
            let start = Arc::clone(&start);
            thread::spawn(move || {
                let trust_store = build_trust_store(&home, ALICE);
                let key_ctx = load_key_context_from_home_path(&home, ALICE);
                let kid = format!("{writer:032X}");
                start.wait();
                trust_store.apply_approvals_with_conflict_handling(
                    vec![TrustApproval::known_key_for_test(
                        format!("writer-{writer}@example.com"),
                        kid,
                    )],
                    &key_ctx,
                    ApprovalConflictHandling::merge(),
                )
            })
        })
        .collect::<Vec<_>>();

    for worker in workers {
        worker
            .join()
            .expect("concurrent writer must not panic")
            .expect("every concurrent writer must commit");
    }

    let key_store = LocalKeyStore::open(home.join("keys")).expect("open keystore");
    let loaded = trust_store
        .load_verified(&key_store)
        .expect("load final trust store")
        .expect("trust store exists");
    assert_eq!(loaded.protected().known_keys.len(), WRITER_COUNT);
}

#[test]
fn test_load_verified_reads_published_snapshot_during_live_staging() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE]);
    let trust_store = build_trust_store(temp.path(), ALICE);
    let key_ctx = load_key_context(&temp, ALICE);
    seed_trust_store(&trust_store, &key_ctx);
    let trust_dir = get_trust_store_dir(temp.path());
    let staging_path = trust_dir.join(format!(".{ALICE}.json.tmp.{LIVE_WRITER_STAGING_UUID}"));
    let home_path = temp.path().to_path_buf();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();

    let worker = with_locked_workspace_dir(&trust_dir, |_| {
        fs::write(&staging_path, "staging").expect("create live staging entry");
        let worker = thread::spawn(move || {
            let key_store = LocalKeyStore::open(home_path.join("keys")).expect("open keystore");
            let trust_store = build_trust_store(&home_path, ALICE);
            started_tx.send(()).expect("signal reader ready");
            let result = trust_store
                .load_verified(&key_store)
                .map(|loaded| loaded.is_some())
                .map_err(|error| error.format_user_message().to_string());
            done_tx.send(result).expect("signal reader done");
        });
        started_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("reader must reach load_verified");
        assert!(done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("reader must not wait for a writer staging another snapshot")
            .expect("reader must load the canonical trust store"));
        fs::remove_file(&staging_path).expect("publish trust store and remove staging entry");
        Ok::<_, kapsaro_core::Error>(worker)
    })
    .expect("hold trust store directory lock");

    worker.join().expect("reader thread must not panic");
}

#[test]
fn test_load_verified_ignores_stale_trust_store_staging_entry() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE]);
    let key_store = LocalKeyStore::open(temp.path().join("keys")).expect("open keystore");
    let trust_store = build_trust_store(temp.path(), ALICE);
    let key_ctx = load_key_context(&temp, ALICE);
    seed_trust_store(&trust_store, &key_ctx);
    let staging_name = format!(".{ALICE}.json.tmp.{STALE_WRITER_STAGING_UUID}");
    let staging_path = get_trust_store_dir(temp.path()).join(&staging_name);
    fs::write(staging_path, "staging").expect("create stale staging entry");

    let loaded = trust_store
        .load_verified(&key_store)
        .expect("staging residue is not a canonical trust store");

    assert!(loaded.is_some());
}

#[cfg(unix)]
#[test]
fn load_verified_uses_opened_keystore_after_root_path_swap() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE]);
    let keys = temp.path().join("keys");
    let original_keys = temp.path().join("keys.original");
    let outside_keys = temp.path().join("outside-keys");
    let key_store = LocalKeyStore::open(&keys).expect("open keystore");
    let trust_store = build_trust_store(temp.path(), ALICE);
    let key_ctx = load_key_context(&temp, ALICE);
    seed_trust_store(&trust_store, &key_ctx);
    fs::rename(&keys, &original_keys).expect("move opened keystore");
    fs::create_dir(&outside_keys).expect("create outside keystore");
    symlink(&outside_keys, &keys).expect("replace keystore path with symlink");

    assert!(trust_store
        .load_verified(&key_store)
        .expect("verify through opened keystore")
        .is_some());
}

#[cfg(unix)]
#[test]
fn apply_approvals_uses_opened_local_state_root_after_path_swap() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE]);
    let home = temp.path().to_path_buf();
    let original_home = home.with_extension("original");
    let outside = TempDir::new().expect("create outside directory");
    let trust_store = build_trust_store(&home, ALICE);
    let key_ctx = load_key_context(&temp, ALICE);
    fs::rename(&home, &original_home).expect("move opened local state root");
    symlink(outside.path(), &home).expect("replace local state root with symlink");

    trust_store
        .apply_approvals_with_conflict_handling(
            vec![TrustApproval::known_key_for_test(BOB, SEED_RECIPIENT_KID)],
            &key_ctx,
            ApprovalConflictHandling::merge(),
        )
        .expect("write through opened local state root");

    assert!(original_home.join(format!("trust/{ALICE}.json")).is_file());
    assert!(!outside.path().join(format!("trust/{ALICE}.json")).exists());
    drop(key_ctx);
    drop(trust_store);
    fs::remove_file(&home).expect("remove replacement symlink");
    fs::rename(&original_home, &home).expect("restore temp directory");
}

#[cfg(unix)]
#[test]
fn apply_approvals_rejects_trust_directory_symlink() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE]);
    let outside = TempDir::new().expect("create outside directory");
    symlink(outside.path(), temp.path().join("trust")).expect("create trust directory symlink");
    let trust_store = build_trust_store(temp.path(), ALICE);
    let key_ctx = load_key_context(&temp, ALICE);

    let error = trust_store
        .apply_approvals_with_conflict_handling(
            Vec::new(),
            &key_ctx,
            ApprovalConflictHandling::merge(),
        )
        .expect_err("trust directory symlink must be rejected");

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
    assert!(!outside.path().join(format!("{ALICE}.json")).exists());
}

#[cfg(unix)]
#[test]
fn load_verified_rejects_trust_file_symlink() {
    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE]);
    let key_store = LocalKeyStore::open(temp.path().join("keys")).expect("open keystore");
    let trust_store = build_trust_store(temp.path(), ALICE);
    let trust_dir = get_trust_store_dir(temp.path());
    create_local_state_dir(&trust_dir);
    let outside = temp.path().join("outside.json");
    fs::write(&outside, "{}").expect("write outside sentinel");
    symlink(&outside, trust_store.path()).expect("create trust file symlink");

    let error = trust_store
        .load_verified(&key_store)
        .expect_err("trust file symlink must be rejected");

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
    assert_eq!(fs::read_to_string(outside).unwrap(), "{}");
}

#[cfg(unix)]
#[test]
fn load_verified_rejects_trust_file_fifo() {
    use std::process::Command;

    let (temp, _workspace) = setup_test_workspace_from_fixtures(&[ALICE]);
    let key_store = LocalKeyStore::open(temp.path().join("keys")).expect("open keystore");
    let trust_store = build_trust_store(temp.path(), ALICE);
    let trust_dir = get_trust_store_dir(temp.path());
    create_local_state_dir(&trust_dir);
    assert!(Command::new("mkfifo")
        .arg(trust_store.path())
        .status()
        .expect("create trust file FIFO")
        .success());

    let error = trust_store
        .load_verified(&key_store)
        .expect_err("trust file FIFO must be rejected");

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
}
