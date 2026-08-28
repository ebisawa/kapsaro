// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;

use crate::api::key::KeyContext;
use crate::app::context::crypto::load_crypto_context_with_access;
use crate::app::context::execution::ExecutionContext;
use crate::app::trust::list::{RecipientSetListItem, TrustListItem};
use crate::app::trust::management::{
    execute_purge, execute_recipient_set_purge, list_purge_candidates,
    list_recipient_set_purge_candidates, remove_known_key_command, remove_recipient_set_command,
    PurgeOutcome, ReviewedPurgeCandidates,
};
use crate::app::trust::store::{
    execute_trust_store_mutation_with_execution, execute_trust_store_mutation_with_prepare_hook,
    TrustStoreWriteBinding,
};
use crate::app_test_utils::{
    build_test_command_options, build_test_execution_context, load_test_trust_store,
    rotate_active_key,
};
use crate::cli_api::test_support::storage::trust::store::save_trust_store;
use crate::feature::trust::recipient_sets::compute_recipient_set_hash;
use crate::feature::trust::signature::sign_trust_store;
use crate::feature::trust::store_mutation::{TrustStoreMutation, TrustStoreMutationMode};
use crate::io::keystore::access::KeystoreAccess;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::trust_store::{
    KnownKey, KnownKeyApprovalVia, RecipientSetApprovalVia, RecipientSetRecord, TrustStoreProtected,
};
use crate::model::wire::format::LOCAL_TRUST_V1;
use crate::support::warning::LocalStateWarningGuard;
use crate::test_utils::ed25519_backend::Ed25519DirectBackend;
use crate::test_utils::{
    local_state_temp_dir, member_handle, setup_member_key_context,
    setup_test_keystore_from_fixtures,
};
use crate::ErrorKind;
use tempfile::TempDir;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const KID_OLD: &str = "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0";
const KID_FRACTIONAL: &str = "C4AR1E00C4AR1E00C4AR1E00C4AR1E00";
const KID_NEW: &str = "D4VE0000D4VE0000D4VE0000D4VE0000";
const ALICE_MEMBER_HANDLE: &str = "alice@example.com";
const SID_OLD: &str = "00000000-0000-4000-8000-000000000001";
const SID_FRACTIONAL: &str = "00000000-0000-4000-8000-000000000002";
const SID_NEW: &str = "00000000-0000-4000-8000-000000000003";

#[test]
fn test_purge_entrypoints_require_reviewed_candidate_types() {
    let _list_known: fn(
        &ExecutionContext,
        OffsetDateTime,
    ) -> crate::Result<ReviewedPurgeCandidates<TrustListItem>> = list_purge_candidates;
    let _execute_known: fn(
        &ExecutionContext,
        &ReviewedPurgeCandidates<TrustListItem>,
    ) -> crate::Result<PurgeOutcome> = execute_purge;
    let _list_recipient_sets: fn(
        &ExecutionContext,
        OffsetDateTime,
    )
        -> crate::Result<ReviewedPurgeCandidates<RecipientSetListItem>> =
        list_recipient_set_purge_candidates;
    let _execute_recipient_sets: fn(
        &ExecutionContext,
        &ReviewedPurgeCandidates<RecipientSetListItem>,
    ) -> crate::Result<PurgeOutcome> = execute_recipient_set_purge;
}

fn build_known_key(kid: &str, member_handle: &str, approved_at: &str) -> KnownKey {
    KnownKey {
        kid: kid.to_string(),
        subject_handle: member_handle.to_string(),
        approved_at: approved_at.to_string(),
        approved_via: KnownKeyApprovalVia::ManualReview,
        evidence: None,
        extra: BTreeMap::new(),
    }
}

fn build_recipient_set(
    sid: &str,
    recipient_kids: &[&str],
    approved_at: &str,
) -> RecipientSetRecord {
    let recipient_kids = recipient_kids
        .iter()
        .map(|kid| (*kid).to_string())
        .collect::<Vec<_>>();
    RecipientSetRecord {
        sid: sid.to_string(),
        recipient_set_hash: compute_recipient_set_hash(&recipient_kids).unwrap(),
        recipient_kids,
        approved_at: approved_at.to_string(),
        approved_via: RecipientSetApprovalVia::ManualReview,
        recipient_handle_hints: None,
    }
}

fn parse_timestamp(ts: &str) -> OffsetDateTime {
    OffsetDateTime::parse(ts, &Rfc3339).unwrap()
}

fn save_signed_trust_store(home: &TempDir) {
    save_signed_trust_store_with_recipient_sets(home, Vec::new());
}

fn save_signed_trust_store_with_recipient_sets(
    home: &TempDir,
    recipient_sets: Vec<RecipientSetRecord>,
) {
    let key_ctx = setup_member_key_context(home, ALICE_MEMBER_HANDLE, None);
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: ALICE_MEMBER_HANDLE.to_string(),
        created_at: "2026-03-29T12:34:56Z".to_string(),
        updated_at: "2026-03-29T12:34:56Z".to_string(),
        known_keys: vec![
            build_known_key(KID_OLD, "bob@example.com", "2026-01-01T00:00:00Z"),
            build_known_key(
                KID_FRACTIONAL,
                "charlie@example.com",
                "2026-01-01T00:00:00.1Z",
            ),
            build_known_key(KID_NEW, "dave@example.com", "2026-06-01T00:00:00Z"),
        ],
        recipient_sets,
    };
    let document = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();
    let path = get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    save_trust_store(&path, &document).unwrap();
}

fn save_signed_trust_store_with_default_recipient_sets(home: &TempDir) {
    save_signed_trust_store_with_recipient_sets(
        home,
        vec![
            build_recipient_set(SID_OLD, &[KID_OLD], "2026-01-01T00:00:00Z"),
            build_recipient_set(SID_FRACTIONAL, &[KID_FRACTIONAL], "2026-01-01T00:00:00.1Z"),
            build_recipient_set(SID_NEW, &[KID_NEW], "2026-06-01T00:00:00Z"),
        ],
    );
}

fn verified_trust_store(home: &TempDir) -> TrustStoreProtected {
    let options = build_test_command_options(home.path(), None);
    load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .unwrap()
        .protected
}

fn build_execution_context_from_home(home: &Path) -> ExecutionContext {
    let access = KeystoreAccess::open_from_home(home).unwrap();
    let ssh_public_key = fs::read_to_string(home.join(".ssh/test_ed25519.pub")).unwrap();
    let backend = Ed25519DirectBackend::new(&home.join(".ssh/test_ed25519")).unwrap();
    let member_handle = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let key_ctx = load_crypto_context_with_access(
        access,
        member_handle.clone(),
        Box::new(backend),
        ssh_public_key,
        None,
        None,
    )
    .unwrap();
    ExecutionContext::from_test_parts(
        member_handle,
        KeyContext::from_inner(key_ctx),
        None,
        Some(home.to_path_buf()),
    )
    .unwrap()
}

#[test]
fn test_remove_known_key_command_rejects_expired_signing_key() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let options = build_test_command_options(home.path(), None);
    crate::test_utils::update_active_private_key_expires_at(
        home.path(),
        ALICE_MEMBER_HANDLE,
        "2020-01-01T00:00:00Z",
    );
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);

    let result = remove_known_key_command(&options, &execution, KID_OLD);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("expired"));
    let loaded = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .unwrap();
    assert!(loaded
        .protected
        .known_keys
        .iter()
        .any(|entry| entry.kid == KID_OLD));
}

#[test]
fn test_remove_recipient_set_command_removes_only_requested_sid() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store_with_default_recipient_sets(&home);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);

    let result = remove_recipient_set_command(&options, &execution, SID_FRACTIONAL).unwrap();

    assert_eq!(result, SID_FRACTIONAL);
    let protected = verified_trust_store(&home);
    assert_eq!(
        protected
            .recipient_sets
            .iter()
            .map(|record| record.sid.as_str())
            .collect::<Vec<_>>(),
        vec![SID_OLD, SID_NEW]
    );
}

#[test]
fn test_trust_mutation_uses_execution_home_after_logical_path_swap() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let options = build_test_command_options(home.path(), None);
    let access = KeystoreAccess::open_from_home(home.path()).unwrap();
    let ssh_public_key = fs::read_to_string(home.path().join(".ssh/test_ed25519.pub")).unwrap();
    let backend = Ed25519DirectBackend::new(&home.path().join(".ssh/test_ed25519")).unwrap();
    let member_handle = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let key_ctx = load_crypto_context_with_access(
        access,
        member_handle.clone(),
        Box::new(backend),
        ssh_public_key,
        None,
        None,
    )
    .unwrap();
    let execution = ExecutionContext::from_test_parts(
        member_handle,
        KeyContext::from_inner(key_ctx),
        None,
        Some(home.path().to_path_buf()),
    )
    .unwrap();
    let moved_parent = local_state_temp_dir();
    let moved_home = moved_parent.path().join("original-home");
    let replacement = local_state_temp_dir();
    fs::rename(home.path(), &moved_home).unwrap();
    symlink(replacement.path(), home.path()).unwrap();

    remove_known_key_command(&options, &execution, KID_OLD).unwrap();

    let moved_options = build_test_command_options(&moved_home, None);
    let loaded = load_test_trust_store(&moved_options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .unwrap();
    assert!(loaded
        .protected
        .known_keys
        .iter()
        .all(|entry| entry.kid != KID_OLD));
    assert!(!replacement.path().join("trust").exists());
}

#[test]
fn test_trust_mutation_snapshot_change_skips_mutation_error() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);
    let path = get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    let mutation_calls = Cell::new(0);

    let error = execute_trust_store_mutation_with_prepare_hook(
        &options,
        &execution,
        TrustStoreMutationMode::ExistingRequired,
        TrustStoreWriteBinding::ObservedDocument,
        |_| {
            mutation_calls.set(mutation_calls.get() + 1);
            Ok(TrustStoreMutation {
                value: (),
                changed: true,
            })
        },
        || {
            let mut replacement = fs::read(&path).unwrap();
            replacement.push(b'\n');
            fs::write(&path, replacement).unwrap();
        },
    )
    .expect_err("changed trust snapshot must stop mutation");

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert_eq!(mutation_calls.get(), 0);
    assert!(fs::read(path).unwrap().ends_with(b"\n"));
}

/// Content that no longer parses is a change from what was reviewed, so the
/// mutation stops as a conflict. Reporting it as a store that must be reset
/// would let a replacement made during the confirmation walk the operator into
/// discarding every pinned key.
#[test]
fn test_reviewed_trust_mutation_reports_unparseable_replacement_as_a_conflict() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);
    let path = get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    let mutation_calls = Cell::new(0);

    let error = execute_trust_store_mutation_with_prepare_hook(
        &options,
        &execution,
        TrustStoreMutationMode::ExistingRequired,
        TrustStoreWriteBinding::ObservedDocument,
        |_| {
            mutation_calls.set(mutation_calls.get() + 1);
            Ok(TrustStoreMutation {
                value: (),
                changed: true,
            })
        },
        || fs::write(&path, "replaced after review").unwrap(),
    )
    .expect_err("a replaced trust store must stop the mutation");

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert_eq!(error.rule(), None);
    assert_eq!(mutation_calls.get(), 0);
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "replaced after review",
        "the replaced store must be left for the operator to inspect"
    );
}

/// A mode that turns unsafe between the review and the write leaves the
/// reviewed content untouched, so the mutation completes and names the file.
#[cfg(unix)]
#[test]
fn test_reviewed_trust_mutation_warns_about_an_unsafe_path_and_completes() {
    use std::os::unix::fs::PermissionsExt;

    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);
    let path = get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));

    let warning_guard = LocalStateWarningGuard::new();
    execute_trust_store_mutation_with_prepare_hook(
        &options,
        &execution,
        TrustStoreMutationMode::ExistingRequired,
        TrustStoreWriteBinding::ObservedDocument,
        |_| {
            Ok(TrustStoreMutation {
                value: (),
                changed: true,
            })
        },
        || {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        },
    )
    .unwrap();
    let warnings = warning_guard.take_reasons();

    assert!(
        warnings.iter().any(|warning| warning.contains("0644")),
        "{warnings:?}"
    );
}

#[test]
fn test_reviewed_trust_mutation_preserves_mutation_parse_error() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);

    let error = execute_trust_store_mutation_with_prepare_hook(
        &options,
        &execution,
        TrustStoreMutationMode::ExistingRequired,
        TrustStoreWriteBinding::ObservedDocument,
        |_| {
            Err::<TrustStoreMutation<()>, _>(crate::Error::build_parse_error(
                "Injected mutation parse failure",
            ))
        },
        || {},
    )
    .expect_err("mutation parse failures must be returned unchanged");

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert_eq!(error.rule(), None);
    assert_eq!(
        error.format_user_message(),
        "Injected mutation parse failure"
    );
}

#[test]
fn test_trust_mutation_missing_snapshot_create_race_skips_mutation_error() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);
    let path = get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    let replacement = fs::read(&path).unwrap();
    fs::remove_file(&path).unwrap();
    let mutation_calls = Cell::new(0);

    let error = execute_trust_store_mutation_with_prepare_hook(
        &options,
        &execution,
        TrustStoreMutationMode::CreateIfMissing,
        TrustStoreWriteBinding::ObservedDocument,
        |_| {
            mutation_calls.set(mutation_calls.get() + 1);
            Ok(TrustStoreMutation {
                value: (),
                changed: true,
            })
        },
        || fs::write(&path, &replacement).unwrap(),
    )
    .expect_err("competing trust store creation must stop mutation");

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert_eq!(mutation_calls.get(), 0);
    assert_eq!(fs::read(path).unwrap(), replacement);
}

#[test]
fn test_trust_mutation_preserves_both_concurrent_known_keys() {
    const FIRST_KID: &str = "E5E00000E5E00000E5E00000E5E00001";
    const SECOND_KID: &str = "E5E00000E5E00000E5E00000E5E00002";

    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let start = Arc::new(Barrier::new(2));
    let home_path = home.path().to_path_buf();
    let writers = [
        (FIRST_KID, "eve@example.com"),
        (SECOND_KID, "frank@example.com"),
    ]
    .into_iter()
    .map(|(kid, member_handle)| {
        let home_path = home_path.clone();
        let start = Arc::clone(&start);
        thread::spawn(move || {
            let options = build_test_command_options(&home_path, None);
            let execution = build_execution_context_from_home(&home_path);
            start.wait();
            execute_trust_store_mutation_with_execution(
                &options,
                &execution,
                TrustStoreMutationMode::ExistingRequired,
                TrustStoreWriteBinding::MergedApproval,
                |protected| {
                    protected.known_keys.push(build_known_key(
                        kid,
                        member_handle,
                        "2026-01-15T00:00:00Z",
                    ));
                    Ok(TrustStoreMutation {
                        value: (),
                        changed: true,
                    })
                },
            )
        })
    })
    .collect::<Vec<_>>();

    for writer in writers {
        writer.join().unwrap().unwrap();
    }

    let protected = verified_trust_store(&home);
    assert!(protected
        .known_keys
        .iter()
        .any(|entry| entry.kid == FIRST_KID));
    assert!(protected
        .known_keys
        .iter()
        .any(|entry| entry.kid == SECOND_KID));
}

#[test]
fn test_remove_known_key_command_accepts_display_kid() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);

    let result = remove_known_key_command(
        &options,
        &execution,
        "B0B0-B0B0-B0B0-B0B0-B0B0-B0B0-B0B0-B0B0",
    )
    .unwrap();

    assert_eq!(result.member_handle, "bob@example.com");
    assert_eq!(result.kid, KID_OLD);
}

#[test]
fn test_remove_known_key_command_accepts_unique_prefix() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);

    let result = remove_known_key_command(&options, &execution, "C4AR").unwrap();

    assert_eq!(result.member_handle, "charlie@example.com");
    assert_eq!(result.kid, KID_FRACTIONAL);
}

#[test]
fn test_execute_purge_rejects_expired_signing_key() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    crate::test_utils::update_active_private_key_expires_at(
        home.path(),
        ALICE_MEMBER_HANDLE,
        "2020-01-01T00:00:00Z",
    );
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);
    let reviewed =
        list_purge_candidates(&execution, parse_timestamp("2026-01-01T00:00:01Z")).unwrap();

    let result = execute_purge(&execution, &reviewed);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("expired"));
    let options = build_test_command_options(home.path(), None);
    let loaded = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .unwrap();
    assert_eq!(loaded.protected.known_keys.len(), 3);
}

#[test]
fn test_execute_purge_rejects_trust_store_changed_after_review() {
    const UNREVIEWED_KID: &str = "E5E00000E5E00000E5E00000E5E00000";

    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);
    let threshold = parse_timestamp("2026-02-01T00:00:00Z");
    let reviewed = list_purge_candidates(&execution, threshold).unwrap();
    let mut protected = verified_trust_store(&home);
    protected.known_keys.push(build_known_key(
        UNREVIEWED_KID,
        "eve@example.com",
        "2026-01-15T00:00:00Z",
    ));
    let key_ctx = setup_member_key_context(&home, ALICE_MEMBER_HANDLE, None);
    let document = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();
    save_trust_store(
        &get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE)),
        &document,
    )
    .unwrap();

    let error = execute_purge(&execution, &reviewed)
        .expect_err("purge must reject content that was not reviewed");

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert!(verified_trust_store(&home)
        .known_keys
        .iter()
        .any(|entry| entry.kid == UNREVIEWED_KID));
}

/// The write-back verifies with the keys read for the listing, so the signer's
/// public half leaving the keystore in between changes nothing: the bytes are
/// still the ones the operator was shown.
#[test]
fn test_execute_purge_verifies_with_the_keys_read_for_the_review() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let signer_kid = setup_member_key_context(&home, ALICE_MEMBER_HANDLE, None)
        .kid()
        .to_string();
    save_signed_trust_store(&home);
    let rotated_kid = rotate_active_key(home.path(), ALICE_MEMBER_HANDLE);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);
    let threshold = parse_timestamp("2026-02-01T00:00:00Z");
    let reviewed = list_purge_candidates(&execution, threshold).unwrap();
    fs::remove_file(
        home.path()
            .join("keys")
            .join(ALICE_MEMBER_HANDLE)
            .join(&signer_kid)
            .join("public.json"),
    )
    .unwrap();

    let outcome = execute_purge(&execution, &reviewed).unwrap();

    assert_eq!(outcome.removed, 2);
    let stored = load_test_trust_store(
        &build_test_command_options(home.path(), None),
        ALICE_MEMBER_HANDLE,
    )
    .unwrap()
    .expect("the purged store must verify against the key that signed it");
    assert_eq!(
        stored.signer_kid.as_ref().map(Kid::as_str),
        Some(rotated_kid.as_str())
    );
    assert_eq!(stored.protected.known_keys.len(), 1);
}

/// A purge that removes nothing can still move the stored signature onto the
/// caller's current signing key. `resigned` is what lets the caller tell that
/// apart from a purge that genuinely left the store untouched.
#[test]
fn test_execute_purge_reports_resign_when_nothing_is_removed() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let rotated_kid = rotate_active_key(home.path(), ALICE_MEMBER_HANDLE);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);
    let threshold = parse_timestamp("2020-01-01T00:00:00Z");
    let reviewed = list_purge_candidates(&execution, threshold).unwrap();

    let outcome = execute_purge(&execution, &reviewed).unwrap();

    assert_eq!(outcome.removed, 0);
    assert!(outcome.resigned);
    let stored = load_test_trust_store(
        &build_test_command_options(home.path(), None),
        ALICE_MEMBER_HANDLE,
    )
    .unwrap()
    .expect("the re-signed store must verify against the rotated key");
    assert_eq!(
        stored.signer_kid.as_ref().map(Kid::as_str),
        Some(rotated_kid.as_str())
    );
}

#[test]
fn test_execute_recipient_set_purge_removes_only_old_records() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store_with_default_recipient_sets(&home);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);
    let threshold = parse_timestamp("2026-01-01T00:00:00.05Z");
    let reviewed = list_recipient_set_purge_candidates(&execution, threshold).unwrap();

    let outcome = execute_recipient_set_purge(&execution, &reviewed).unwrap();

    assert_eq!(outcome.removed, 1);
    assert!(!outcome.resigned);
    let protected = verified_trust_store(&home);
    assert_eq!(
        protected
            .recipient_sets
            .iter()
            .map(|record| record.sid.as_str())
            .collect::<Vec<_>>(),
        vec![SID_FRACTIONAL, SID_NEW]
    );
}

#[test]
fn test_purge_candidate_lists_require_an_existing_trust_store() {
    for create_trust_directory in [false, true] {
        let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
        if create_trust_directory {
            crate::test_utils::create_local_state_dir(&home.path().join("trust"));
        }
        let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);
        let threshold = parse_timestamp("2026-01-01T00:00:00Z");
        let errors = [
            list_purge_candidates(&execution, threshold)
                .expect_err("known-key purge listing requires a trust store"),
            list_recipient_set_purge_candidates(&execution, threshold)
                .expect_err("recipient purge listing requires a trust store"),
        ];

        assert!(errors
            .iter()
            .all(|error| error.kind() == ErrorKind::NotFound));
        assert!(errors
            .iter()
            .all(|error| error.to_string().contains("Trust store not found")));
    }
}

#[test]
fn test_recipient_set_mutation_rejects_expired_signing_key_without_store_change() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store_with_default_recipient_sets(&home);
    let options = build_test_command_options(home.path(), None);
    crate::test_utils::update_active_private_key_expires_at(
        home.path(),
        ALICE_MEMBER_HANDLE,
        "2020-01-01T00:00:00Z",
    );
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);

    let result = remove_recipient_set_command(&options, &execution, SID_OLD);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("expired"));
    let protected = verified_trust_store(&home);
    assert_eq!(
        protected
            .recipient_sets
            .iter()
            .map(|record| record.sid.as_str())
            .collect::<Vec<_>>(),
        vec![SID_OLD, SID_FRACTIONAL, SID_NEW]
    );
}

#[test]
fn test_list_recipient_set_purge_candidates_returns_only_old_records() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store_with_default_recipient_sets(&home);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);

    let result =
        list_recipient_set_purge_candidates(&execution, parse_timestamp("2026-01-01T00:00:00.05Z"))
            .unwrap();

    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].sid, SID_OLD);
}

#[cfg(unix)]
#[test]
fn test_remove_known_key_command_warns_about_insecure_permission() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);
    let trust_path = get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    let warning_guard = LocalStateWarningGuard::new();
    remove_known_key_command(&options, &execution, KID_OLD).unwrap();
    let warnings = warning_guard.take_reasons();

    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].contains("Insecure permissions 0644"),
        "{warnings:?}"
    );
    assert!(warnings[0].contains("chmod 0600"), "{warnings:?}");
}

/// A removal on a home that has no trust store reports the store as missing
/// and leaves the local state as it found it.
#[test]
fn test_remove_known_key_command_reports_missing_store_without_creating_the_directory() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);

    let error = remove_known_key_command(&options, &execution, KID_OLD)
        .expect_err("a removal without a trust store must fail");

    assert_eq!(error.kind(), ErrorKind::NotFound);
    assert!(!home.path().join("trust").exists());
}
