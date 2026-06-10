// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer key management command tests.
//! Covers key list/export orchestration and local keystore mutations.

use std::path::Path;

use crate::test_utils::{
    build_test_private_key, keygen_test, setup_test_keystore_from_fixtures, ALICE_MEMBER_HANDLE,
    BOB_MEMBER_HANDLE,
};
use kapsaro_core::api::secret::SecretString;
use kapsaro_core::cli_api::app::context::options::CommonCommandOptions;
use kapsaro_core::cli_api::app::context::ssh::SshSigningContextResolution;
use kapsaro_core::cli_api::app::key::manage::{
    activate_key_command, export_key_command, export_private_key_command, list_keys_command,
    remove_key_command,
};
use kapsaro_core::cli_api::presentation::kid::format_kid_display;
use kapsaro_core::cli_api::test_support::domain::ssh::SshDeterminismStatus;
use kapsaro_core::cli_api::test_support::storage::keystore::active::load_active_kid;
use kapsaro_core::cli_api::test_support::storage::keystore::storage::save_key_pair_atomic;
use kapsaro_core::cli_api::test_support::storage::ssh::protocol::fingerprint::build_sha256_fingerprint;

fn build_options(home: &Path) -> CommonCommandOptions {
    CommonCommandOptions {
        home: Some(home.to_path_buf()),
        identity: None,
        debug: false,
        verbose: false,
        workspace: None,
        ssh_signing_method: None,
        allow_expired_key: false,
        allow_non_member: false,
    }
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
    let options = build_options(temp_dir.path());

    let result = list_keys_command(&options, None).unwrap();

    assert_eq!(result.total_keys, 1);
    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].0, ALICE_MEMBER_HANDLE);
    assert_eq!(result.entries[0].1.len(), 1);
    assert!(result.entries[0].1[0].active);
}

#[test]
fn test_list_keys_command_filtered_by_member_handle() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    add_second_key(&temp_dir, BOB_MEMBER_HANDLE);
    let options = build_options(temp_dir.path());

    let alice = list_keys_command(&options, Some(ALICE_MEMBER_HANDLE.to_string())).unwrap();
    let bob = list_keys_command(&options, Some(BOB_MEMBER_HANDLE.to_string())).unwrap();

    assert_eq!(alice.total_keys, 1);
    assert_eq!(alice.entries[0].0, ALICE_MEMBER_HANDLE);
    assert_eq!(bob.total_keys, 1);
    assert_eq!(bob.entries[0].0, BOB_MEMBER_HANDLE);
}

#[test]
fn test_export_key_command_active_key() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let options = build_options(temp_dir.path());
    let out = temp_dir.path().join("exported-public.json");

    let result =
        export_key_command(&options, Some(ALICE_MEMBER_HANDLE.to_string()), None, &out).unwrap();

    assert_eq!(result.member_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(
        result.public_key.protected.subject_handle,
        ALICE_MEMBER_HANDLE
    );
    assert!(out.exists());
}

#[test]
fn test_export_key_command_explicit_display_kid() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");
    let active_kid = load_active_kid(ALICE_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .unwrap();
    let options = build_options(temp_dir.path());
    let out = temp_dir.path().join("exported-public.json");

    let result = export_key_command(
        &options,
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
    let options = build_options(temp_dir.path());
    let password = SecretString::new("correct horse battery staple".to_string());
    let ssh_ctx = build_test_ssh_context(temp_dir.path());

    let result = export_private_key_command(
        &options,
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
    let options = build_options(temp_dir.path());

    let result = activate_key_command(
        &options,
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
    let options = build_options(temp_dir.path());

    let result =
        activate_key_command(&options, Some(ALICE_MEMBER_HANDLE.to_string()), None).unwrap();

    assert_eq!(result.member_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(result.kid, second_kid);
}

#[test]
fn test_activate_key_command_not_found() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let options = build_options(temp_dir.path());

    let result = activate_key_command(
        &options,
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
    let options = build_options(temp_dir.path());

    let result = remove_key_command(
        &options,
        None,
        format_kid_display(&second_kid).unwrap().to_lowercase(),
        false,
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
    let options = build_options(temp_dir.path());

    let result = remove_key_command(
        &options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        active_kid,
        false,
    );

    assert!(result.is_err());
    let msg = format!("{}", result.err().unwrap());
    assert!(
        msg.contains("active") || msg.contains("force"),
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
    let options = build_options(temp_dir.path());

    let result = remove_key_command(
        &options,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        active_kid.clone(),
        true,
    )
    .unwrap();

    assert_eq!(result.kid, active_kid);
    assert!(result.was_active);

    let current_active = load_active_kid(ALICE_MEMBER_HANDLE, &keystore_root).unwrap();
    assert!(current_active.is_none());
}

fn build_test_ssh_context(home: &Path) -> SshSigningContextResolution {
    let ssh_private_key_path = home.join(".ssh/test_ed25519");
    let ssh_public_key = std::fs::read_to_string(home.join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let backend =
        crate::test_utils::ed25519_backend::Ed25519DirectBackend::new(&ssh_private_key_path)
            .unwrap();

    SshSigningContextResolution {
        fingerprint: build_sha256_fingerprint(&ssh_public_key).unwrap(),
        public_key: ssh_public_key,
        backend: Box::new(backend),
        determinism: SshDeterminismStatus::Verified,
    }
}
