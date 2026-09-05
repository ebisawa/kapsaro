// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use crate::io::trust::paths::get_trust_store_file_path;
use crate::model::trust_store::RecipientSetRecord;
use crate::service::config::LocalStateSession;
use crate::service::trust::list::{
    list_known_keys_command, list_recipient_sets_command,
    resolve_trust_list_command as resolve_trust_list_command_with_session, TrustListCommand,
};
use crate::service::trust::recovery::{
    build_trust_store_reset_plan_from_list_command, observe_trust_store_recovery_from_list_command,
};
use crate::service_test_utils::{
    build_known_key, build_recipient_set, save_trust_store_signed_by_active_key,
};
use crate::test_utils::{
    ensure_local_state_dir, local_state_temp_dir, member_handle, save_local_state_file,
    setup_test_keystore_from_fixtures,
};
use tempfile::TempDir;

const KID_BOB: &str = "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0";
const KID_CHARLIE: &str = "C4AR1E00C4AR1E00C4AR1E00C4AR1E00";
const ALICE_MEMBER_HANDLE: &str = "alice@example.com";
const SID_ENV_FILE: &str = "00000000-0000-4000-8000-000000000101";
const STORED_AT: &str = "2026-03-29T12:34:56Z";

fn resolve_trust_list_command(
    path: &std::path::Path,
    owner: crate::model::identity::MemberHandle,
) -> crate::Result<TrustListCommand> {
    let local_state = LocalStateSession::open(path.to_path_buf())?;
    resolve_trust_list_command_with_session(&local_state, owner)
}

fn save_signed_trust_store(home: &TempDir) {
    save_signed_trust_store_with_recipient_sets(home, Vec::new());
}

fn save_signed_trust_store_with_recipient_sets(
    home: &TempDir,
    recipient_sets: Vec<RecipientSetRecord>,
) {
    save_trust_store_signed_by_active_key(
        home,
        ALICE_MEMBER_HANDLE,
        STORED_AT,
        vec![
            build_known_key(KID_BOB, "bob@example.com", Some("2026-03-29T12:40:00Z")),
            build_known_key(
                KID_CHARLIE,
                "charlie@example.com",
                Some("2026-03-29T12:41:00Z"),
            ),
        ],
        recipient_sets,
    );
}

fn install_member_fixture(home: &TempDir, member_handle: &str) {
    let source_home = setup_test_keystore_from_fixtures(member_handle);
    fs::rename(
        source_home.path().join("keys").join(member_handle),
        home.path().join("keys").join(member_handle),
    )
    .unwrap();
}

fn save_invalid_trust_store(home: &TempDir, owner: &str) {
    let path = get_trust_store_file_path(home.path(), &member_handle(owner));
    ensure_local_state_dir(path.parent().unwrap());
    save_local_state_file(&path, "invalid");
}

#[test]
fn test_list_known_keys_succeeds_without_ssh_signing_method() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);

    let command =
        resolve_trust_list_command(home.path(), member_handle(ALICE_MEMBER_HANDLE)).unwrap();
    let result = list_known_keys_command(&command).unwrap();

    assert_eq!(result.items.len(), 2);
    assert_eq!(result.items[0].kid, KID_BOB);
    assert_eq!(result.items[1].kid, KID_CHARLIE);
}

#[test]
fn test_list_recipient_sets_returns_empty_when_store_is_missing() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let command =
        resolve_trust_list_command(home.path(), member_handle(ALICE_MEMBER_HANDLE)).unwrap();
    let result = list_recipient_sets_command(&command).unwrap();

    assert!(result.items.is_empty());
}

#[test]
fn test_list_recipient_sets_preserves_signed_store_fields() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let recipient_set = build_recipient_set(
        SID_ENV_FILE,
        &[KID_BOB, KID_CHARLIE],
        "2026-03-29T12:42:00Z",
    );
    let expected_hash = recipient_set.recipient_set_hash.clone();
    save_signed_trust_store_with_recipient_sets(&home, vec![recipient_set]);
    let command =
        resolve_trust_list_command(home.path(), member_handle(ALICE_MEMBER_HANDLE)).unwrap();
    let result = list_recipient_sets_command(&command).unwrap();

    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].sid, SID_ENV_FILE);
    assert_eq!(result.items[0].recipient_set_hash, expected_hash);
    assert_eq!(
        result.items[0].recipient_kids,
        vec![KID_BOB.to_string(), KID_CHARLIE.to_string()]
    );
}

#[test]
fn test_trust_list_with_explicit_owner_keeps_missing_home_absent() {
    let parent = local_state_temp_dir();
    let missing_home = parent.path().join("missing-home");
    let command =
        resolve_trust_list_command(&missing_home, member_handle(ALICE_MEMBER_HANDLE)).unwrap();
    let keys = list_known_keys_command(&command).unwrap();
    let recipients = list_recipient_sets_command(&command).unwrap();

    assert!(keys.items.is_empty());
    assert!(recipients.items.is_empty());
    assert!(!missing_home.exists());
}

#[test]
fn test_trust_list_with_document_and_missing_keystore_preserves_document() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    save_signed_trust_store(&home);
    fs::remove_dir_all(home.path().join("keys")).unwrap();
    let command =
        resolve_trust_list_command(home.path(), member_handle(ALICE_MEMBER_HANDLE)).unwrap();
    let token = observe_trust_store_recovery_from_list_command(&command);
    let error = list_known_keys_command(&command).unwrap_err();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some("E_LOCAL_KEYSTORE_MISSING"));
    let plan_error = build_trust_store_reset_plan_from_list_command(&command, token, error, true)
        .expect_err("missing local keystore must not create a reset plan");

    assert_eq!(plan_error.recovery(), Some("E_LOCAL_KEYSTORE_MISSING"));
    assert!(get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE)).exists());
}

#[test]
fn test_trust_list_command_keeps_explicit_owner() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    install_member_fixture(&home, "bob@example.com");
    let recipient_set = build_recipient_set(
        SID_ENV_FILE,
        &[KID_BOB, KID_CHARLIE],
        "2026-03-29T12:42:00Z",
    );
    save_signed_trust_store_with_recipient_sets(&home, vec![recipient_set]);
    save_invalid_trust_store(&home, "bob@example.com");
    let command =
        resolve_trust_list_command(home.path(), member_handle(ALICE_MEMBER_HANDLE)).unwrap();

    let keys = list_known_keys_command(&command).unwrap();
    let recipients = list_recipient_sets_command(&command).unwrap();

    assert_eq!(keys.items.len(), 2);
    assert_eq!(recipients.items.len(), 1);
    let replacement_command =
        resolve_trust_list_command(home.path(), member_handle("bob@example.com")).unwrap();
    assert!(list_known_keys_command(&replacement_command).is_err());
}

#[cfg(unix)]
#[test]
fn test_trust_list_command_keeps_home_after_path_swap() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let replacement_home = setup_test_keystore_from_fixtures("bob@example.com");
    let recipient_set = build_recipient_set(
        SID_ENV_FILE,
        &[KID_BOB, KID_CHARLIE],
        "2026-03-29T12:42:00Z",
    );
    save_signed_trust_store_with_recipient_sets(&home, vec![recipient_set]);
    save_invalid_trust_store(&replacement_home, "bob@example.com");
    let command =
        resolve_trust_list_command(home.path(), member_handle(ALICE_MEMBER_HANDLE)).unwrap();
    let opened_home = home.path().with_extension("opened");
    fs::rename(home.path(), &opened_home).unwrap();
    fs::rename(replacement_home.path(), home.path()).unwrap();

    let keys = list_known_keys_command(&command).unwrap();
    let recipients = list_recipient_sets_command(&command).unwrap();

    assert_eq!(keys.items.len(), 2);
    assert_eq!(recipients.items.len(), 1);
    let replacement_command =
        resolve_trust_list_command(home.path(), member_handle("bob@example.com")).unwrap();
    assert!(list_known_keys_command(&replacement_command).is_err());
    drop(replacement_command);
    drop(command);
    fs::rename(home.path(), replacement_home.path()).unwrap();
    fs::rename(opened_home, home.path()).unwrap();
}
