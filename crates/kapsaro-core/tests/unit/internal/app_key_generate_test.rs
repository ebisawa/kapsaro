// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Internal tests for the key generation use case.
//! Covers what reaches the keystore and remains recoverable after failure.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::{
    build_activation_failure_error, ensure_kid_not_in_keystore, generate_and_save_key_with_access,
    publish_generated_key, AppKeyGenerationOptions, KeyGenerationHome,
};
use crate::app_test_utils::add_generated_key;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::ssh::protocol::build_sha256_fingerprint;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::ssh::SshDeterminismStatus;
use crate::service::config::LocalStateSession;
use crate::service::online::OnlineVerificationStatus;
use crate::service::ssh::SshSigningContextResolution;
use crate::support::warning::LocalStateWarningGuard;
use crate::test_utils::{
    create_local_state_dir, local_state_temp_dir, setup_test_keystore_from_fixtures,
    ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE,
};
use crate::{Error, ErrorKind};

/// The signing environment a generated key is attested with.
fn build_test_ssh_context(home: &Path) -> SshSigningContextResolution {
    let ssh_private_key_path = home.join(".ssh/test_ed25519");
    let ssh_public_key = fs::read_to_string(home.join(".ssh/test_ed25519.pub"))
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

fn key_dir(home: &Path, member_handle: &str, kid: &Kid) -> std::path::PathBuf {
    home.join("keys").join(member_handle).join(kid.as_str())
}

fn open_fixture_keystore(home: &Path) -> KeystoreAccess {
    KeystoreAccess::open(home.join("keys")).unwrap()
}

#[test]
fn test_ensure_kid_not_in_keystore_passes_when_absent() {
    let dir = local_state_temp_dir();
    let access = KeystoreAccess::create(dir.path()).unwrap();
    let result = ensure_kid_not_in_keystore(&access, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD");

    assert!(result.is_ok());
}

#[test]
fn test_ensure_kid_not_in_keystore_fails_when_present_any_member() {
    let dir = local_state_temp_dir();
    let keystore_root = dir.path();
    create_local_state_dir(&keystore_root.join("alice@example.com"));
    create_local_state_dir(
        &keystore_root
            .join("alice@example.com")
            .join("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
    );

    let access = KeystoreAccess::open(keystore_root).unwrap();
    let err = ensure_kid_not_in_keystore(&access, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD").unwrap_err();
    let msg = format!("{err}");

    assert!(msg.contains("already exists in keystore"));
    assert!(msg.contains("alice@example.com"));
}

/// Pointing the local state root at another volume through a symlink is a
/// supported setup, so the keystore is created behind the link.
#[cfg(unix)]
#[test]
fn test_key_generation_home_creates_the_keystore_through_an_explicit_home_symlink() {
    use std::os::unix::fs::symlink;

    let temp = local_state_temp_dir();
    let outside = temp.path().join("outside");
    let home = temp.path().join("home");
    create_local_state_dir(&outside);
    symlink(&outside, &home).unwrap();

    let local_state = LocalStateSession::open(&home).unwrap();
    let access = KeyGenerationHome::fix(&local_state)
        .unwrap()
        .ensure_keystore_access()
        .unwrap();

    assert_eq!(access.root(), home.join("keys"));
    assert!(outside.join("keys").is_dir());
}

#[test]
fn test_key_generation_home_creates_an_absent_local_state_home() {
    let temp = local_state_temp_dir();
    let home = temp.path().join("home");
    let local_state = LocalStateSession::open(&home).unwrap();
    let access = KeyGenerationHome::fix(&local_state)
        .unwrap()
        .ensure_keystore_access()
        .unwrap();

    assert_eq!(access.root(), home.join("keys"));
    assert!(home.join("keys").is_dir());
}

/// The local state directory is fixed before the SSH identity and the GitHub
/// binding are settled, and those take an operator at the terminal. A path
/// repointed while they run therefore changes nothing about where the key
/// lands: the write goes through the directory the command opened.
#[cfg(unix)]
#[test]
fn test_a_key_lands_in_the_home_fixed_at_the_start_after_the_path_is_repointed() {
    use std::os::unix::fs::symlink;

    let temp = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let started_in = temp.path().join("started-in");
    let repointed_to = temp.path().join("repointed-to");
    let home = temp.path().join("home");
    create_local_state_dir(&started_in);
    create_local_state_dir(&repointed_to);
    symlink(&started_in, &home).unwrap();

    let local_state = LocalStateSession::open(&home).unwrap();
    fs::remove_file(&home).unwrap();
    symlink(&repointed_to, &home).unwrap();
    let fixed = KeyGenerationHome::fix(&local_state).unwrap();

    let saved = generate_and_save_key_with_access(AppKeyGenerationOptions {
        member_handle: BOB_MEMBER_HANDLE.to_string(),
        home: fixed,
        created_at: "2020-01-01T00:00:00Z".to_string(),
        expires_at: "2999-01-01T00:00:00Z".to_string(),
        no_activate: false,
        github_account: None,
        github_verification: OnlineVerificationStatus::NotConfigured,
        ssh_ctx: build_test_ssh_context(temp.path()),
    })
    .expect("the fixed directory is still writable after the path moved");

    assert!(started_in
        .join("keys")
        .join(BOB_MEMBER_HANDLE)
        .join(&saved.result.kid)
        .is_dir());
    assert!(!repointed_to.join("keys").exists());
}

/// The expiry is resolved when the command starts and the key is stored after
/// the SSH and GitHub steps, so it is checked once more immediately before the
/// write. A key whose expiry has been reached by then never enters the
/// keystore, where it would sit unusable because activation refuses it.
#[test]
fn test_a_key_whose_expiry_was_reached_never_enters_the_keystore() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let ssh_ctx = build_test_ssh_context(home.path());

    let saved = generate_and_save_key_with_access(AppKeyGenerationOptions {
        member_handle: BOB_MEMBER_HANDLE.to_string(),
        home: KeyGenerationHome::fix(&LocalStateSession::open(home.path()).unwrap()).unwrap(),
        created_at: "2020-01-01T00:00:00Z".to_string(),
        expires_at: "2021-01-01T00:00:00Z".to_string(),
        no_activate: false,
        github_account: None,
        github_verification: OnlineVerificationStatus::NotConfigured,
        ssh_ctx,
    });

    let Err(error) = saved else {
        panic!("a key that is already expired must not be stored");
    };

    assert_eq!(error.kind(), ErrorKind::Config);
    assert!(
        error.to_string().contains("already be expired"),
        "unexpected message: {error}"
    );
    assert!(!home.path().join("keys").join(BOB_MEMBER_HANDLE).exists());
}

/// A stored pair is already published even when the later activation fails.
/// Keeping both halves lets the operator inspect, retry, or remove that exact
/// key without losing material that another process may already have observed.
#[test]
fn test_activation_failure_keeps_the_stored_pair_and_explains_recovery() {
    let _warning_guard = LocalStateWarningGuard::new();
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let kid = add_generated_key(home.path(), ALICE_MEMBER_HANDLE);
    let access = open_fixture_keystore(home.path());
    let member_handle = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let active_before = access.load_active_kid(&member_handle).unwrap();
    let stored_key_dir = key_dir(home.path(), ALICE_MEMBER_HANDLE, &kid);
    fs::set_permissions(
        stored_key_dir.join("private.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();

    let error = publish_generated_key(&access, &member_handle, &kid, false).unwrap_err();

    let message = error.to_string();
    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PRIVATE_KEY_EXPOSED"));
    assert!(
        message.contains(kid.as_str()),
        "unexpected message: {error}"
    );
    let member_option = format!("--member-handle {member_handle}");
    assert!(
        message.contains(&format!("kapsaro key list {member_option}")),
        "unexpected message: {error}"
    );
    assert!(
        message.contains(&format!("kapsaro key activate {kid} {member_option}")),
        "unexpected message: {error}"
    );
    assert!(
        message.contains(&format!("kapsaro key remove {kid} {member_option}")),
        "unexpected message: {error}"
    );
    assert!(stored_key_dir.join("private.json").is_file());
    assert!(stored_key_dir.join("public.json").is_file());
    assert_eq!(
        access.load_active_kid(&member_handle).unwrap(),
        active_before
    );
}

#[test]
fn test_activation_failure_context_preserves_error_metadata() {
    let kid = Kid::try_from("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD").unwrap();
    let io_error = Error::build_io_error_with_source(
        "activation failed",
        std::io::Error::other("marker unavailable"),
    )
    .with_recovery("E_TEST_RECOVERY");

    let member_handle = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let io_error = build_activation_failure_error(&member_handle, &kid, io_error);

    assert_eq!(io_error.kind(), ErrorKind::Io);
    assert_eq!(io_error.recovery(), Some("E_TEST_RECOVERY"));
    assert_eq!(
        std::error::Error::source(&io_error).unwrap().to_string(),
        "marker unavailable"
    );

    let verification_error = build_activation_failure_error(
        &member_handle,
        &kid,
        Error::build_verification_error("V-TEST-ACTIVATION", "activation failed"),
    );
    assert_eq!(verification_error.kind(), ErrorKind::Verify);
    assert_eq!(verification_error.rule(), Some("V-TEST-ACTIVATION"));
}
