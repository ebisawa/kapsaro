// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer key management command tests.
//! Covers key list/export orchestration and local keystore mutations.

use std::path::Path;

use crate::test_utils::{
    build_test_private_key, keygen_test, local_state_temp_dir, setup_test_keystore_from_fixtures,
    ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE,
};
use kapsaro_core::api::config::LocalStateSession;
use kapsaro_core::api::key::manage::{
    activate_key_command, export_key_command, export_private_key_command, list_keys_command,
    remove_key_command,
};
use kapsaro_core::api::key::types::KeyInfo;
use kapsaro_core::api::key::MemberHandle;
use kapsaro_core::api::secret::SecretString;
use kapsaro_core::api::ssh::{SshSigningContextResolution, SshSigningInputs, SshSigningMethod};
use kapsaro_core::api::trust::TrustCommandSession;
use kapsaro_core::test_support::helpers::kid::format_kid_display;
use kapsaro_core::test_support::storage::keystore::active::load_active_kid;
use kapsaro_core::test_support::storage::keystore::storage::save_key_pair_atomic;

/// Signing capability for a keystore that holds no trust store to re-sign.
fn unreachable_resign(_member_handle: &MemberHandle) -> kapsaro_core::Result<TrustCommandSession> {
    panic!("a keystore without a trust store must not re-sign one");
}

fn add_second_key(temp_dir: &tempfile::TempDir, member_handle: &str) -> String {
    let keystore_root = temp_dir.path().join("keys");
    let ssh_pub_content = std::fs::read_to_string(temp_dir.path().join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let ssh_priv = temp_dir.path().join(".ssh/test_ed25519");
    let (priv_plain, pub_key) = keygen_test(member_handle, &ssh_priv, &ssh_pub_content).unwrap();
    let kid = pub_key.protected.kid.clone();
    let priv_key = build_test_private_key(
        &priv_plain,
        member_handle,
        &kid,
        &ssh_priv,
        &ssh_pub_content,
    )
    .unwrap();

    save_key_pair_atomic(&keystore_root, member_handle, &kid, &priv_key, &pub_key).unwrap();

    kid
}

#[test]
fn test_list_keys_command_single_member() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let result = list_keys_command(temp_dir.path(), None).unwrap();

    assert_eq!(result.total_keys, 1);
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].0, ALICE_MEMBER_HANDLE);
    assert_eq!(result.entries[0].1.len(), 1);
    assert!(matches!(
        result.entries[0].1[0],
        KeyInfo::Complete { active: true, .. }
    ));
}

/// A local state root that holds no keystore holds no keys, so the listing is
/// empty. Every other key command acts on a key and still refuses.
#[test]
fn test_list_keys_command_without_a_keystore_lists_nothing() {
    let temp_dir = local_state_temp_dir();
    let result = list_keys_command(temp_dir.path(), None).unwrap();

    assert_eq!(result.total_keys, 0);
    assert!(result.entries.is_empty());
}

#[test]
fn test_list_keys_command_filtered_by_member_handle() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    add_second_key(&temp_dir, BOB_MEMBER_HANDLE);
    let alice = list_keys_command(temp_dir.path(), Some(ALICE_MEMBER_HANDLE.to_string())).unwrap();
    let bob = list_keys_command(temp_dir.path(), Some(BOB_MEMBER_HANDLE.to_string())).unwrap();

    assert_eq!(alice.total_keys, 1);
    assert_eq!(alice.entries[0].0, ALICE_MEMBER_HANDLE);
    assert_eq!(bob.total_keys, 1);
    assert_eq!(bob.entries[0].0, BOB_MEMBER_HANDLE);
}

#[test]
fn test_list_keys_command_includes_an_incomplete_active_key() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let complete_kid = add_second_key(&temp_dir, ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");
    let active_kid = load_active_kid(ALICE_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .unwrap();
    std::fs::remove_file(
        keystore_root
            .join(ALICE_MEMBER_HANDLE)
            .join(&active_kid)
            .join("public.json"),
    )
    .unwrap();
    let result = list_keys_command(temp_dir.path(), Some(ALICE_MEMBER_HANDLE.to_string())).unwrap();

    assert_eq!(result.total_keys, 2);
    assert_eq!(result.entries[0].1.len(), 2);
    assert!(result.entries[0].1.iter().any(|key| matches!(
        key,
        KeyInfo::Incomplete {
            kid,
            member_handle,
            active: true,
            missing_document,
        } if kid == &active_kid
            && member_handle == ALICE_MEMBER_HANDLE
            && missing_document.as_str() == "public.json"
    )));
    assert!(result.entries[0].1.iter().any(|key| matches!(
        key,
        KeyInfo::Complete { kid, active: false, .. } if kid == &complete_kid
    )));
}

#[test]
fn test_export_key_command_active_key() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let out = temp_dir.path().join("exported-public.json");

    let result = export_key_command(
        temp_dir.path(),
        Some(ALICE_MEMBER_HANDLE.to_string()),
        None,
        &out,
    )
    .unwrap();

    assert_eq!(result.member_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(
        result.public_key.protected.subject_handle,
        ALICE_MEMBER_HANDLE
    );
    assert!(out.exists());
}

/// An export reads the keystore and writes the file the caller named, so a
/// workspace it never touches is not something it has to resolve first.
#[test]
fn test_export_key_command_writes_without_resolving_a_workspace() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let out = temp_dir.path().join("exported-public.json");

    let result = export_key_command(
        temp_dir.path(),
        Some(ALICE_MEMBER_HANDLE.to_string()),
        None,
        &out,
    )
    .unwrap();

    assert_eq!(result.member_handle, ALICE_MEMBER_HANDLE);
    assert!(out.exists());
}

#[test]
fn test_export_key_command_explicit_display_kid() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");
    let active_kid = load_active_kid(ALICE_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .unwrap();
    let out = temp_dir.path().join("exported-public.json");

    let result = export_key_command(
        temp_dir.path(),
        Some(ALICE_MEMBER_HANDLE.to_string()),
        Some(format_kid_display(&active_kid).unwrap().to_lowercase()),
        &out,
    )
    .unwrap();

    assert_eq!(result.kid, active_kid);
}

#[test]
fn test_export_private_key_command_reencrypts_active_key() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");
    let active_kid = load_active_kid(ALICE_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .unwrap();
    let password = SecretString::new("correct horse battery staple".to_string());
    let ssh_ctx = build_test_ssh_context(temp_dir.path());

    let result = export_private_key_command(
        temp_dir.path(),
        ALICE_MEMBER_HANDLE.to_string(),
        None,
        &password,
        false,
        ssh_ctx,
    )
    .unwrap();

    assert_eq!(result.member_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(result.kid, active_kid);
    assert!(!result.encoded_key.as_str().is_empty());
    assert!(result.password_warning.is_none());
}

#[test]
fn test_activate_key_command_explicit_kid() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let second_kid = add_second_key(&temp_dir, ALICE_MEMBER_HANDLE);
    let result = activate_key_command(
        temp_dir.path(),
        Some(ALICE_MEMBER_HANDLE.to_string()),
        Some(format_kid_display(&second_kid).unwrap().to_lowercase()),
    )
    .unwrap();

    assert_eq!(result.member_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(result.kid, second_kid);
}

#[test]
fn test_activate_key_command_auto_select_latest() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    std::thread::sleep(std::time::Duration::from_secs(1));
    let second_kid = add_second_key(&temp_dir, ALICE_MEMBER_HANDLE);
    let result =
        activate_key_command(temp_dir.path(), Some(ALICE_MEMBER_HANDLE.to_string()), None).unwrap();

    assert_eq!(result.member_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(result.kid, second_kid);
}

#[test]
fn test_activate_key_command_not_found() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let result = activate_key_command(
        temp_dir.path(),
        Some(ALICE_MEMBER_HANDLE.to_string()),
        Some("00000000000000000000000000000001".to_string()),
    );

    assert!(result.is_err());
    let msg = format!("{}", result.err().unwrap());
    assert!(
        msg.contains("not found") || msg.contains("Not found"),
        "unexpected error: {msg}"
    );
}

#[test]
fn test_remove_key_command_non_active() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let second_kid = add_second_key(&temp_dir, ALICE_MEMBER_HANDLE);
    let result = remove_key_command(
        temp_dir.path(),
        None,
        format_kid_display(&second_kid).unwrap().to_lowercase(),
        false,
        unreachable_resign,
    )
    .unwrap();

    assert_eq!(result.member_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(result.kid, second_kid);
    assert!(!result.was_active);
}

#[test]
fn test_remove_key_command_active_without_force() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");
    let active_kid = load_active_kid(ALICE_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .unwrap();
    let result = remove_key_command(
        temp_dir.path(),
        Some(ALICE_MEMBER_HANDLE.to_string()),
        active_kid,
        false,
        unreachable_resign,
    );

    assert!(result.is_err());
    let msg = format!("{}", result.err().unwrap());
    assert!(
        msg.contains("kapsaro key activate <other-kid> --member-handle alice@example.com"),
        "unexpected error: {msg}"
    );
}

#[test]
fn test_remove_key_command_active_with_force() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");
    let active_kid = load_active_kid(ALICE_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .unwrap();
    let result = remove_key_command(
        temp_dir.path(),
        Some(ALICE_MEMBER_HANDLE.to_string()),
        active_kid.clone(),
        true,
        unreachable_resign,
    )
    .unwrap();

    assert_eq!(result.kid, active_kid);
    assert!(result.was_active);

    let current_active = load_active_kid(ALICE_MEMBER_HANDLE, &keystore_root).unwrap();
    assert!(current_active.is_none());
}

fn build_test_ssh_context(home: &Path) -> SshSigningContextResolution {
    let ssh_private_key_path = home.join(".ssh/test_ed25519");
    let local_state = LocalStateSession::open(home).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let store = local_state.require_key_store(&member).unwrap();
    let inputs = SshSigningInputs::new(
        SshSigningMethod::SshKeygen,
        Some(ssh_private_key_path),
        None,
        "ssh-keygen",
        "ssh-add",
    );
    store
        .resolve_signing_context(member, None, &inputs, false)
        .unwrap()
        .1
}
