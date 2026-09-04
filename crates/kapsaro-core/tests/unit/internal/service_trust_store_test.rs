// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests trust-store loading behavior for partially initialized local state.
//! Verifies absent trust documents do not require an existing keystore.

use crate::feature::trust::signature::sign_trust_store;
use crate::feature::trust::store_mutation::TrustStoreMutation;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::trust_store::{KnownKey, KnownKeyApprovalVia, TrustStoreProtected};
use crate::model::wire::format::LOCAL_TRUST_V1;
use crate::service::trust::store::{
    execute_trust_store_mutation_with_session,
    execute_trust_store_mutation_with_session_prepare_hook, load_optional_trust_store,
    trust_store_or_empty,
};
use crate::service_test_utils::{
    build_test_command_options, build_test_trust_command_session, load_test_trust_store,
    rotate_active_key, save_trust_store_signed_by_active_key,
};
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::{open_optional_child_dir, DirectoryScope};
use crate::test_support::storage::trust::store::save_trust_store;
use crate::test_utils::ensure_local_state_dir;
use crate::test_utils::{
    member_handle, setup_member_key_context, setup_test_keystore_from_fixtures,
};
use std::collections::BTreeMap;
use std::fs;
use tempfile::TempDir;

const OWNER: &str = "alice@example.com";
const OTHER_OWNER: &str = "bob@example.com";
const OTHER_KID: &str = "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0";
const STORED_AT: &str = "2026-03-29T12:34:56Z";

#[test]
fn test_trust_store_or_empty_returns_empty_store_when_keys_are_absent() {
    let home = TempDir::new().unwrap();
    ensure_local_state_dir(&home.path().join("trust"));
    let base = AnchoredDir::open(
        home.path(),
        DirectoryScope::LocalState,
        "test local state root",
    )
    .unwrap();
    let trust_dir = open_optional_child_dir(&base, "trust").unwrap().unwrap();
    let owner = MemberHandle::try_from(OWNER).unwrap();

    let loaded = load_optional_trust_store(&base, Some(&trust_dir), &owner, None)
        .expect("an absent trust document does not need a keystore");
    let loaded = trust_store_or_empty(&owner, loaded).unwrap();

    assert_eq!(loaded.protected.owner_handle, OWNER);
    assert!(loaded.protected.known_keys.is_empty());
    assert!(loaded.protected.recipient_sets.is_empty());
}

#[test]
fn test_invalid_trust_store_error_wraps_signature_failure_once() {
    let home = setup_test_keystore_from_fixtures(OWNER);
    let key_ctx = setup_member_key_context(&home, OWNER, None);
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: OWNER.to_string(),
        created_at: "2026-03-29T12:34:56Z".to_string(),
        updated_at: "2026-03-29T12:34:56Z".to_string(),
        known_keys: Vec::new(),
        recipient_sets: Vec::new(),
    };
    let mut document = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();
    let replacement = if document.signature.sig.starts_with('A') {
        'B'
    } else {
        'A'
    };
    document.signature.sig = format!("{replacement}{}", &document.signature.sig[1..]);
    let path = get_trust_store_file_path(home.path(), &member_handle(OWNER));
    save_trust_store(&path, &document).unwrap();
    let base = AnchoredDir::open(
        home.path(),
        DirectoryScope::LocalState,
        "test local state root",
    )
    .unwrap();
    let trust_dir = open_optional_child_dir(&base, "trust").unwrap().unwrap();
    let owner = MemberHandle::try_from(OWNER).unwrap();

    let error = match load_optional_trust_store(&base, Some(&trust_dir), &owner, None) {
        Ok(_) => panic!("signature-invalid trust store must fail verification"),
        Err(error) => error,
    };

    assert_eq!(error.recovery(), Some("E_TRUST_STORE_RESET_REQUIRED"));
    assert_eq!(
        error
            .format_user_message()
            .matches("is invalid and must be reset")
            .count(),
        1
    );
}

#[test]
fn test_load_optional_trust_store_reports_missing_local_keystore() {
    let home = setup_test_keystore_from_fixtures(OWNER);
    let key_ctx = setup_member_key_context(&home, OWNER, None);
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: OWNER.to_string(),
        created_at: "2026-03-29T12:34:56Z".to_string(),
        updated_at: "2026-03-29T12:34:56Z".to_string(),
        known_keys: Vec::new(),
        recipient_sets: Vec::new(),
    };
    let document = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();
    let path = get_trust_store_file_path(home.path(), &member_handle(OWNER));
    save_trust_store(&path, &document).unwrap();
    std::fs::remove_dir_all(home.path().join("keys")).unwrap();
    let base = AnchoredDir::open(
        home.path(),
        DirectoryScope::LocalState,
        "test local state root",
    )
    .unwrap();
    let trust_dir = open_optional_child_dir(&base, "trust").unwrap().unwrap();
    let owner = MemberHandle::try_from(OWNER).unwrap();

    let error = match load_optional_trust_store(&base, Some(&trust_dir), &owner, None) {
        Err(error) => error,
        Ok(_) => panic!("a trust document without a verification keystore must fail"),
    };

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some("E_LOCAL_KEYSTORE_MISSING"));
    assert!(error
        .format_user_message()
        .contains(&home.path().join("keys").display().to_string()));
    assert!(error.format_user_message().contains("--home"));
    assert!(error.format_user_message().contains("KAPSARO_HOME"));
}

#[cfg(unix)]
#[test]
fn test_load_optional_trust_store_reports_unsafe_keystore_path() {
    use std::os::unix::fs::symlink;

    let home = setup_test_keystore_from_fixtures(OWNER);
    let key_ctx = setup_member_key_context(&home, OWNER, None);
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: OWNER.to_string(),
        created_at: "2026-03-29T12:34:56Z".to_string(),
        updated_at: "2026-03-29T12:34:56Z".to_string(),
        known_keys: Vec::new(),
        recipient_sets: Vec::new(),
    };
    let document = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();
    let trust_path = get_trust_store_file_path(home.path(), &member_handle(OWNER));
    save_trust_store(&trust_path, &document).unwrap();
    std::fs::remove_dir_all(home.path().join("keys")).unwrap();
    let external_keys = TempDir::new().unwrap();
    symlink(external_keys.path(), home.path().join("keys")).unwrap();
    let base = AnchoredDir::open(
        home.path(),
        DirectoryScope::LocalState,
        "test local state root",
    )
    .unwrap();
    let trust_dir = open_optional_child_dir(&base, "trust").unwrap().unwrap();
    let owner = MemberHandle::try_from(OWNER).unwrap();

    let error = match load_optional_trust_store(&base, Some(&trust_dir), &owner, None) {
        Err(error) => error,
        Ok(_) => panic!("a symlinked keystore must be rejected"),
    };
    let message = error.format_user_message();

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
    assert!(message.contains(&home.path().join("keys").display().to_string()));
    assert!(!message.contains(&trust_path.display().to_string()));
}

fn save_active_key_signed_trust_store(home: &TempDir) {
    save_trust_store_signed_by_active_key(home, OWNER, STORED_AT, Vec::new(), Vec::new());
}

fn unchanged_mutation(
    _protected: &mut TrustStoreProtected,
) -> crate::Result<TrustStoreMutation<()>> {
    Ok(TrustStoreMutation {
        value: (),
        changed: false,
    })
}

fn add_known_key_mutation(
    protected: &mut TrustStoreProtected,
) -> crate::Result<TrustStoreMutation<()>> {
    protected.known_keys.push(KnownKey {
        kid: OTHER_KID.to_string(),
        subject_handle: OTHER_OWNER.to_string(),
        approved_at: STORED_AT.to_string(),
        approved_via: KnownKeyApprovalVia::ManualReview,
        evidence: None,
        extra: BTreeMap::new(),
    });
    Ok(TrustStoreMutation {
        value: (),
        changed: true,
    })
}

/// The commit verifies whatever the exclusive lock finds against keys read
/// before that lock was taken, so a keystore that is gone by then changes
/// nothing. Taking the signer key away between the two steps is what proves the
/// member directory is never opened while the trust lock is held.
#[test]
fn test_commit_verifies_with_the_keys_read_before_the_trust_lock() {
    let home = setup_test_keystore_from_fixtures(OWNER);
    let signer_kid =
        save_trust_store_signed_by_active_key(&home, OWNER, STORED_AT, Vec::new(), Vec::new());
    let session = build_test_trust_command_session(&home, OWNER);
    let signer_key_dir = home.path().join("keys").join(OWNER).join(&signer_kid);

    execute_trust_store_mutation_with_session_prepare_hook(
        &session,
        add_known_key_mutation,
        move || fs::remove_dir_all(&signer_key_dir).unwrap(),
    )
    .unwrap();

    assert_eq!(
        read_stored_trust_store(&home)["protected"]["known_keys"][0]["kid"],
        OTHER_KID
    );
}

fn read_stored_trust_store(home: &TempDir) -> serde_json::Value {
    let path = get_trust_store_file_path(home.path(), &member_handle(OWNER));
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn test_serialized_mutation_resigns_without_touching_updated_at() {
    let home = setup_test_keystore_from_fixtures(OWNER);
    save_active_key_signed_trust_store(&home);
    let rotated_kid = rotate_active_key(home.path(), OWNER);
    let options = build_test_command_options(home.path(), None);
    let session = build_test_trust_command_session(&home, OWNER);

    execute_trust_store_mutation_with_session(&session, unchanged_mutation).unwrap();

    let stored = load_test_trust_store(&options, OWNER)
        .unwrap()
        .expect("the re-signed store must verify against the rotated key");
    assert_eq!(
        stored.signer_kid.as_ref().map(Kid::as_str),
        Some(rotated_kid.as_str())
    );
    assert_eq!(stored.protected.updated_at, STORED_AT);
}

#[test]
fn test_reviewed_mutation_resigns_without_touching_updated_at() {
    let home = setup_test_keystore_from_fixtures(OWNER);
    save_active_key_signed_trust_store(&home);
    let rotated_kid = rotate_active_key(home.path(), OWNER);
    let options = build_test_command_options(home.path(), None);
    let session = build_test_trust_command_session(&home, OWNER);

    execute_trust_store_mutation_with_session_prepare_hook(&session, unchanged_mutation, || {})
        .unwrap();

    let stored = load_test_trust_store(&options, OWNER)
        .unwrap()
        .expect("the re-signed store must verify against the rotated key");
    assert_eq!(
        stored.signer_kid.as_ref().map(Kid::as_str),
        Some(rotated_kid.as_str())
    );
    assert_eq!(stored.protected.updated_at, STORED_AT);
}

#[test]
fn test_unchanged_mutation_by_the_signing_key_leaves_the_stored_bytes_alone() {
    let home = setup_test_keystore_from_fixtures(OWNER);
    save_active_key_signed_trust_store(&home);
    let path = get_trust_store_file_path(home.path(), &member_handle(OWNER));
    let before = fs::read(&path).unwrap();
    let session = build_test_trust_command_session(&home, OWNER);

    execute_trust_store_mutation_with_session(&session, unchanged_mutation).unwrap();

    assert_eq!(fs::read(&path).unwrap(), before);
}

/// A signer key that left the keystore costs the stored approvals, so the
/// report has to name the way to get them back before anything discards them.
#[test]
fn test_missing_signer_key_error_offers_the_recovery_route_first() {
    let home = setup_test_keystore_from_fixtures(OWNER);
    save_active_key_signed_trust_store(&home);
    let rotated_kid = rotate_active_key(home.path(), OWNER);
    let options = build_test_command_options(home.path(), None);
    let session = build_test_trust_command_session(&home, OWNER);
    execute_trust_store_mutation_with_session(&session, unchanged_mutation).unwrap();
    // The mutation above handed the signature to the rotated key, so taking
    // that key away is what leaves the stored document without a signer.
    fs::remove_dir_all(
        home.path()
            .join("keys")
            .join(OWNER)
            .join(rotated_kid.as_str()),
    )
    .unwrap();

    let error = match load_test_trust_store(&options, OWNER) {
        Err(error) => error,
        Ok(_) => panic!("a trust store whose signer key is gone cannot be verified"),
    };
    let message = error.format_user_message();

    assert_eq!(error.recovery(), Some("E_TRUST_SIGNER_KEY_MISSING"));
    assert!(message.contains("public.json"), "got: {message}");
    assert!(message.contains("kapsaro trust resign"), "got: {message}");
    assert!(
        message.contains("trusted backup or known-good copy"),
        "got: {message}"
    );
    assert!(message.contains("owner-only permissions"), "got: {message}");
    assert!(message.contains("reset the trust store"), "got: {message}");
    assert!(!message.contains("kapsaro key export"), "got: {message}");
}
