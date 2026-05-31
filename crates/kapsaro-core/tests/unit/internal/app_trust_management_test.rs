// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::app::trust::management::{
    execute_purge, execute_recipient_set_purge, list_recipient_set_purge_candidates,
    remove_known_key_command, remove_recipient_set_command,
};
use crate::app_test_utils::{build_test_command_options, build_test_execution_context};
use crate::feature::trust::recipient_sets::compute_recipient_set_hash;
use crate::feature::trust::signature::sign_trust_store;
use crate::feature::trust::verification::verify_trust_store;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::io::trust::store::{load_trust_store, save_trust_store};
use crate::model::trust_store::{
    KnownKey, KnownKeyApprovalVia, RecipientSetApprovalVia, RecipientSetRecord, TrustStoreProtected,
};
use crate::model::wire::format::LOCAL_TRUST_V1;
use crate::test_utils::{setup_member_key_context, setup_test_keystore_from_fixtures};
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
    let path = get_trust_store_file_path(home.path(), ALICE_MEMBER_HANDLE);
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
    let loaded = load_trust_store(
        &get_trust_store_file_path(home.path(), ALICE_MEMBER_HANDLE),
        home.path(),
    )
    .unwrap()
    .unwrap();
    verify_trust_store(&loaded.document, &home.path().join("keys"))
        .unwrap()
        .document()
        .protected
        .clone()
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

    let result = remove_known_key_command(&options, &execution, KID_OLD, false);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("expired"));
    let loaded = load_trust_store(
        &get_trust_store_file_path(home.path(), ALICE_MEMBER_HANDLE),
        home.path(),
    )
    .unwrap()
    .unwrap();
    let verified = verify_trust_store(&loaded.document, &home.path().join("keys")).unwrap();
    assert!(verified
        .document()
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

    let result = remove_recipient_set_command(&options, &execution, SID_FRACTIONAL, false).unwrap();

    assert_eq!(result.value, SID_FRACTIONAL);
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
fn test_remove_known_key_command_accepts_display_kid() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);

    let result = remove_known_key_command(
        &options,
        &execution,
        "B0B0-B0B0-B0B0-B0B0-B0B0-B0B0-B0B0-B0B0",
        false,
    )
    .unwrap();

    assert_eq!(result.value.member_handle, "bob@example.com");
    assert_eq!(result.value.kid, KID_OLD);
}

#[test]
fn test_remove_known_key_command_accepts_unique_prefix() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);

    let result = remove_known_key_command(&options, &execution, "C4AR", false).unwrap();

    assert_eq!(result.value.member_handle, "charlie@example.com");
    assert_eq!(result.value.kid, KID_FRACTIONAL);
}

#[test]
fn test_execute_purge_rejects_expired_signing_key() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let options = build_test_command_options(home.path(), None);
    crate::test_utils::update_active_private_key_expires_at(
        home.path(),
        ALICE_MEMBER_HANDLE,
        "2020-01-01T00:00:00Z",
    );
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);

    let result = execute_purge(
        &options,
        &execution,
        parse_timestamp("2026-01-01T00:00:01Z"),
        false,
    );

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("expired"));
    let loaded = load_trust_store(
        &get_trust_store_file_path(home.path(), ALICE_MEMBER_HANDLE),
        home.path(),
    )
    .unwrap()
    .unwrap();
    let verified = verify_trust_store(&loaded.document, &home.path().join("keys")).unwrap();
    assert_eq!(verified.document().protected.known_keys.len(), 3);
}

#[test]
fn test_execute_recipient_set_purge_removes_only_old_records() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store_with_default_recipient_sets(&home);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);

    let result = execute_recipient_set_purge(
        &options,
        &execution,
        parse_timestamp("2026-01-01T00:00:00.05Z"),
        false,
    )
    .unwrap();

    assert_eq!(result.value, 1);
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

    let result = remove_recipient_set_command(&options, &execution, SID_OLD, false);

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
    let options = build_test_command_options(home.path(), None);

    let result = list_recipient_set_purge_candidates(
        &options,
        ALICE_MEMBER_HANDLE,
        parse_timestamp("2026-01-01T00:00:00.05Z"),
    )
    .unwrap();

    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].sid, SID_OLD);
}

#[cfg(unix)]
#[test]
fn test_remove_known_key_command_surfaces_insecure_permission_warning() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    let options = build_test_command_options(home.path(), None);
    let execution = build_test_execution_context(&home, ALICE_MEMBER_HANDLE, None);
    let trust_path = get_trust_store_file_path(home.path(), ALICE_MEMBER_HANDLE);
    fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o644)).unwrap();

    let result = remove_known_key_command(&options, &execution, KID_OLD, false).unwrap();

    assert_eq!(result.value.member_handle, "bob@example.com");
    assert_eq!(result.value.kid, KID_OLD);
    assert!(!result.warnings.is_empty());
    assert!(result
        .warnings
        .iter()
        .any(|warning| warning.contains("Insecure permissions")));
}
