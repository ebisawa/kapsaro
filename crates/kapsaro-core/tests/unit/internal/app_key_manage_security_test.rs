// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Security regressions for application-layer key management.
//! Ensures owner resolution, the trust signer guard, and mutation stay bound to one keystore.

use std::cell::Cell;
use std::fs;
use std::path::Path;

use super::{activate_key_command, remove_key_command, set_post_member_resolution_hook};
use crate::api::key::KeyContext;
use crate::app::context::execution::ExecutionContext;
use crate::app::context::options::CommonCommandOptions;
use crate::app_test_utils::{
    add_generated_key, load_test_trust_store, rotate_active_key,
    save_test_trust_store_signed_by_active_key,
};
use crate::error::TRUST_STORE_RESET_REQUIRED_RECOVERY;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::model::identity::{Kid, MemberHandle};
use crate::test_utils::{
    member_handle, setup_member_key_context, setup_test_keystore_from_fixtures, ALICE_MEMBER_HANDLE,
};
use crate::{Error, ErrorKind};
use tempfile::TempDir;

fn build_options(home: &Path) -> CommonCommandOptions {
    CommonCommandOptions::new().with_home(Some(home.to_path_buf()))
}

fn add_second_key(home: &Path) -> Kid {
    add_generated_key(home, ALICE_MEMBER_HANDLE)
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir(destination).unwrap();
    fs::set_permissions(destination, fs::metadata(source).unwrap().permissions()).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_directory(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn swap_keystore_path(home: &Path) {
    fs::rename(home.join("keys"), home.join("keys.original")).unwrap();
    fs::rename(home.join("keys.replacement"), home.join("keys")).unwrap();
}

/// Put an empty trust directory where the command resolved the stored one.
fn swap_trust_directory(home: &Path) {
    fs::rename(home.join("trust"), home.join("trust.original")).unwrap();
    fs::create_dir(home.join("trust")).unwrap();
}

/// Put a second trust directory holding the same document where the stored one was.
///
/// The copy verifies exactly like the original, so nothing downstream can tell
/// the two apart by content: only the directory identity says which document a
/// step is acting on.
fn swap_trust_directory_with_copy(home: &Path) {
    fs::rename(home.join("trust"), home.join("trust.original")).unwrap();
    copy_directory(&home.join("trust.original"), &home.join("trust"));
}

#[cfg(unix)]
#[test]
fn test_activate_reuses_resolved_keystore_after_path_swap() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let second_kid = add_second_key(home.path());
    copy_directory(
        &home.path().join("keys"),
        &home.path().join("keys.replacement"),
    );
    let options = build_options(home.path());

    let swap_home = home.path().to_path_buf();
    set_post_member_resolution_hook(move || swap_keystore_path(&swap_home));

    activate_key_command(&options, None, Some(second_kid.to_string())).unwrap();

    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let original = KeystoreAccess::open(home.path().join("keys.original")).unwrap();
    let replacement = KeystoreAccess::open(home.path().join("keys")).unwrap();
    assert_eq!(
        original.load_active_kid(&member).unwrap(),
        Some(second_kid.clone())
    );
    assert_ne!(
        replacement.load_active_kid(&member).unwrap(),
        Some(second_kid)
    );
}

#[cfg(unix)]
#[test]
fn test_remove_reuses_resolved_keystore_after_path_swap() {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let second_kid = add_second_key(home.path());
    copy_directory(
        &home.path().join("keys"),
        &home.path().join("keys.replacement"),
    );
    let options = build_options(home.path());

    let swap_home = home.path().to_path_buf();
    set_post_member_resolution_hook(move || swap_keystore_path(&swap_home));

    remove_key_command(
        &options,
        None,
        second_kid.to_string(),
        false,
        unreachable_resign,
    )
    .unwrap();

    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let original = KeystoreAccess::open(home.path().join("keys.original")).unwrap();
    let replacement = KeystoreAccess::open(home.path().join("keys")).unwrap();
    assert!(!original.list_kids(&member).unwrap().contains(&second_kid));
    assert!(replacement
        .list_kids(&member)
        .unwrap()
        .contains(&second_kid));
}

const STORED_AT: &str = "2026-03-29T12:34:56Z";

/// A trust store that will not verify, reported the way a real read reports it:
/// still the failure it was, and naming a reset as the route past it.
fn build_reset_required_error() -> Error {
    Error::build_parse_error("Local trust store is invalid and must be reset")
        .with_recovery(TRUST_STORE_RESET_REQUIRED_RECOVERY)
}

/// Signing capability for a removal that must never ask for one.
fn unreachable_resign(_member_handle: &MemberHandle) -> crate::Result<ExecutionContext> {
    panic!("removing a key that does not sign the trust store must not re-sign it");
}

/// Signing capability for a removal the keystore settles before the hand-over.
fn unreachable_handover(_member_handle: &MemberHandle) -> crate::Result<ExecutionContext> {
    panic!("a removal the keystore refuses must not reach the trust store hand-over");
}

fn signed_home() -> (TempDir, String) {
    let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let signer_kid =
        save_test_trust_store_signed_by_active_key(&home, ALICE_MEMBER_HANDLE, STORED_AT);
    (home, signer_kid)
}

/// Signing identity a hand-over is given, bound to one key of the owner.
///
/// `kid` selects the key that signs; `None` takes the member's active key, which
/// is what the CLI resolves for a removal.
fn signing_execution(home: &TempDir, kid: Option<&str>) -> ExecutionContext {
    ExecutionContext::from_test_parts(
        MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap(),
        KeyContext::from_inner(setup_member_key_context(home, ALICE_MEMBER_HANDLE, kid)),
        None,
        Some(home.path().to_path_buf()),
    )
    .unwrap()
}

/// Rewrite the stored trust store so this build can no longer read it.
///
/// A document written in a later format is the case that must not be read as
/// "no signer": the stored approvals are intact and still signed, only this
/// build cannot say by which key.
fn store_unreadable_trust_store(home: &TempDir) {
    let path = get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE));
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    document["protected"]["format"] =
        serde_json::Value::String("kapsaro:format:local-trust@2".to_string());
    fs::write(&path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
}

fn key_dir(home: &TempDir, kid: &str) -> std::path::PathBuf {
    home.path().join("keys").join(ALICE_MEMBER_HANDLE).join(kid)
}

#[test]
fn test_removing_a_key_that_does_not_sign_the_trust_store_skips_re_signing() {
    let (home, _signer_kid) = signed_home();
    let spare_kid = add_generated_key(home.path(), ALICE_MEMBER_HANDLE);
    let options = build_options(home.path());

    let result = remove_key_command(
        &options,
        None,
        spare_kid.to_string(),
        false,
        unreachable_resign,
    )
    .unwrap();

    assert_eq!(result.kid, spare_kid.as_str());
    assert!(result.resigned_trust_store_kid.is_none());
    assert!(result.trust_store_warning.is_none());
}

#[test]
fn test_removing_the_signer_key_re_signs_before_the_key_is_gone() {
    let (home, signer_kid) = signed_home();
    let rotated_kid = rotate_active_key(home.path(), ALICE_MEMBER_HANDLE);
    let options = build_options(home.path());
    let signer_dir = key_dir(&home, &signer_kid);
    let called = Cell::new(false);

    let result = remove_key_command(&options, None, signer_kid.clone(), false, |member_handle| {
        assert_eq!(member_handle.as_str(), ALICE_MEMBER_HANDLE);
        assert!(
            signer_dir.exists(),
            "the trust store must be re-signed while the old signer key is still readable"
        );
        called.set(true);
        Ok(signing_execution(&home, None))
    })
    .unwrap();

    assert!(called.get());
    assert_eq!(
        result.resigned_trust_store_kid.as_deref(),
        Some(rotated_kid.as_str())
    );
    assert!(result.trust_store_warning.is_none());
    assert!(!signer_dir.exists());
    let stored = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .expect("the stored trust store must still verify after the removal");
    assert_eq!(
        stored.signer_kid.as_ref().map(Kid::as_str),
        Some(rotated_kid.as_str())
    );
}

#[test]
fn test_removing_the_only_signer_key_is_refused() {
    let (home, signer_kid) = signed_home();
    let options = build_options(home.path());

    let error = remove_key_command(
        &options,
        None,
        signer_kid.clone(),
        false,
        unreachable_resign,
    )
    .expect_err("the last key able to sign the trust store must not be removed");

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some("E_TRUST_SIGNER_KEY_IN_USE"));
    assert!(
        error
            .format_user_message()
            .contains("kapsaro key activate <other-kid> --member-handle alice@example.com"),
        "{}",
        error.format_user_message()
    );
    assert!(home
        .path()
        .join("keys")
        .join(ALICE_MEMBER_HANDLE)
        .join(&signer_kid)
        .exists());
}

#[test]
fn test_forced_removal_of_the_only_signer_key_reports_how_to_restore_it() {
    let (home, signer_kid) = signed_home();
    let options = build_options(home.path());

    let result =
        remove_key_command(&options, None, signer_kid.clone(), true, unreachable_resign).unwrap();

    let warning = result
        .trust_store_warning
        .expect("a forced removal of the trust store signer must report the consequence");
    assert!(warning.contains("kapsaro trust resign --member-handle alice@example.com"));
    assert!(warning.contains("public.json"));
    assert!(warning.contains("trusted backup or known-good copy"));
    assert!(warning.contains("owner-only permissions"));
    assert!(
        warning.contains("the key this member has active"),
        "{warning}"
    );
    assert!(warning.contains("review the approvals again"), "{warning}");
    assert!(result.resigned_trust_store_kid.is_none());
    assert!(!home
        .path()
        .join("keys")
        .join(ALICE_MEMBER_HANDLE)
        .join(&signer_kid)
        .exists());
}

/// `--force` covers a removal the guard would refuse; it does not skip a
/// hand-over that can succeed, which costs the operator nothing.
#[test]
fn test_forced_removal_of_the_signer_key_still_hands_the_signature_over() {
    let (home, signer_kid) = signed_home();
    let rotated_kid = rotate_active_key(home.path(), ALICE_MEMBER_HANDLE);
    let options = build_options(home.path());
    let called = Cell::new(false);

    let result = remove_key_command(&options, None, signer_kid.clone(), true, |_member_handle| {
        called.set(true);
        Ok(signing_execution(&home, None))
    })
    .unwrap();

    assert!(called.get());
    assert_eq!(
        result.resigned_trust_store_kid.as_deref(),
        Some(rotated_kid.as_str())
    );
    assert!(result.trust_store_warning.is_none());
}

/// Activation writes no signature, so it reports the key the stored trust
/// store still leans on instead of moving it.
#[test]
fn test_activate_reports_the_key_the_trust_store_is_still_signed_by() {
    let (home, signer_kid) = signed_home();
    let spare_kid = add_generated_key(home.path(), ALICE_MEMBER_HANDLE);
    let options = build_options(home.path());

    let result = activate_key_command(&options, None, Some(spare_kid.to_string())).unwrap();

    assert_eq!(result.kid, spare_kid.as_str());
    assert_eq!(
        result.trust_store_signer_kid.as_deref(),
        Some(signer_kid.as_str())
    );
    assert!(result.trust_store_warning.is_none());
}

/// A trust store that will not verify names no signer, and saying nothing about
/// it would let the activation read as complete while the approvals it reports
/// on cannot be read at all. The reason travels back so the CLI reports it.
#[test]
fn test_activate_reports_a_trust_store_it_could_not_read() {
    let (home, _signer_kid) = signed_home();
    let spare_kid = add_generated_key(home.path(), ALICE_MEMBER_HANDLE);
    store_unreadable_trust_store(&home);
    let options = build_options(home.path());

    let result = activate_key_command(&options, None, Some(spare_kid.to_string())).unwrap();

    assert_eq!(result.kid, spare_kid.as_str());
    assert!(result.trust_store_signer_kid.is_none());
    let warning = result
        .trust_store_warning
        .expect("an unreadable trust store must be reported");
    assert!(warning.contains("could not be read"), "{warning}");
}

/// A hand-over that cannot happen is not a reason to keep the key forever.
///
/// The signature may be impossible to move for reasons that have nothing to do
/// with the stored approvals: no ssh-agent, an active key that has expired, a
/// trust store that no longer verifies. `--force` covers all of them the same
/// way it covers a removal with no other key to sign at all.
#[test]
fn test_forced_removal_proceeds_when_the_signature_cannot_be_handed_over() {
    let (home, signer_kid) = signed_home();
    let rotated_kid = rotate_active_key(home.path(), ALICE_MEMBER_HANDLE);
    let options = build_options(home.path());

    let result = remove_key_command(&options, None, signer_kid.clone(), true, |_member_handle| {
        Err(build_reset_required_error())
    })
    .unwrap();

    let warning = result
        .trust_store_warning
        .expect("a removal that could not hand the signature over must say so");
    assert!(warning.contains("must be reset"), "{warning}");
    assert!(
        warning.contains("kapsaro trust resign --member-handle alice@example.com"),
        "{warning}"
    );
    assert!(warning.contains("public.json"), "{warning}");
    assert!(result.resigned_trust_store_kid.is_none());
    assert!(!home
        .path()
        .join("keys")
        .join(ALICE_MEMBER_HANDLE)
        .join(&signer_kid)
        .exists());
    assert!(home
        .path()
        .join("keys")
        .join(ALICE_MEMBER_HANDLE)
        .join(rotated_kid.as_str())
        .exists());
}

/// Without `--force` the failure stands, so the operator can repair the store
/// and keep the approvals rather than losing them by default.
#[test]
fn test_removal_without_force_stops_when_the_signature_cannot_be_handed_over() {
    let (home, signer_kid) = signed_home();
    let _rotated_kid = rotate_active_key(home.path(), ALICE_MEMBER_HANDLE);
    let options = build_options(home.path());

    let error = remove_key_command(
        &options,
        None,
        signer_kid.clone(),
        false,
        |_member_handle| Err(build_reset_required_error()),
    )
    .expect_err("a hand-over that failed must stop a removal that was not forced");

    assert_eq!(error.recovery(), Some("E_TRUST_STORE_RESET_REQUIRED"));
    assert!(home
        .path()
        .join("keys")
        .join(ALICE_MEMBER_HANDLE)
        .join(&signer_kid)
        .exists());
}

/// Content this build cannot read names no signer and rules none out either, so
/// the key being removed may well be the one the approvals hang on. The removal
/// stops instead of going ahead on a signature nobody could look at.
#[test]
fn test_removal_stops_when_the_stored_trust_store_cannot_be_read() {
    let (home, signer_kid) = signed_home();
    store_unreadable_trust_store(&home);
    let options = build_options(home.path());

    let error = remove_key_command(
        &options,
        None,
        signer_kid.clone(),
        false,
        unreachable_resign,
    )
    .expect_err("a trust store nothing can read must not let a key be removed silently");

    assert_eq!(error.kind(), ErrorKind::Schema);
    assert_eq!(error.recovery(), Some("E_TRUST_STORE_RESET_REQUIRED"));
    assert!(key_dir(&home, &signer_kid).exists());
}

/// The same removal is the operator's to accept, once they are told the store
/// could not be read and what taking the key back would require.
#[test]
fn test_forced_removal_reports_a_trust_store_that_could_not_be_read() {
    let (home, signer_kid) = signed_home();
    store_unreadable_trust_store(&home);
    let options = build_options(home.path());

    let result =
        remove_key_command(&options, None, signer_kid.clone(), true, unreachable_resign).unwrap();

    let warning = result
        .trust_store_warning
        .expect("a forced removal past an unreadable trust store must report it");
    assert!(warning.contains("could not be read"), "{warning}");
    assert!(warning.contains("trust resign"), "{warning}");
    assert!(warning.contains("public.json"), "{warning}");
    assert!(result.resigned_trust_store_kid.is_none());
    assert!(!key_dir(&home, &signer_kid).exists());
}

/// The guard reads the trust store through the directory the command opened, so
/// a directory swapped in afterwards cannot make the stored signature look
/// absent and let its signer key be removed as an unrelated one.
#[cfg(unix)]
#[test]
fn test_removal_classifies_through_the_trust_directory_it_opened() {
    let (home, signer_kid) = signed_home();
    let _rotated_kid = rotate_active_key(home.path(), ALICE_MEMBER_HANDLE);
    let options = build_options(home.path());

    let swap_home = home.path().to_path_buf();
    set_post_member_resolution_hook(move || swap_trust_directory(&swap_home));

    let error = remove_key_command(
        &options,
        None,
        signer_kid.clone(),
        false,
        |_member_handle| Err(Error::build_io_error("hand-over was requested")),
    )
    .expect_err("the stored signature must still be seen through the opened directory");

    assert!(
        error
            .format_user_message()
            .contains("hand-over was requested"),
        "{}",
        error.format_user_message()
    );
    assert!(key_dir(&home, &signer_kid).exists());
}

/// The hand-over resolves its signing identity from the configured path, which
/// reaches the trust directory a second time. It is bound to the directory the
/// removal was decided against, so a store swapped in behind that path is
/// reported as a conflict and left exactly as it stands.
#[cfg(unix)]
#[test]
fn test_hand_over_is_refused_when_the_signing_identity_resolves_another_trust_directory() {
    let (home, signer_kid) = signed_home();
    let _rotated_kid = rotate_active_key(home.path(), ALICE_MEMBER_HANDLE);
    let options = build_options(home.path());

    let swap_home = home.path().to_path_buf();
    set_post_member_resolution_hook(move || swap_trust_directory_with_copy(&swap_home));

    let error = remove_key_command(
        &options,
        None,
        signer_kid.clone(),
        false,
        |_member_handle| Ok(signing_execution(&home, None)),
    )
    .expect_err("a hand-over must not re-sign a trust store the removal never looked at");

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert!(
        error
            .format_user_message()
            .contains("local trust directory"),
        "{}",
        error.format_user_message()
    );
    let swapped = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .expect("the swapped-in trust store must still be there");
    assert_eq!(
        swapped.signer_kid.as_ref().map(Kid::as_str),
        Some(signer_kid.as_str())
    );
    assert!(key_dir(&home, &signer_kid).exists());
}

/// The hand-over resolves its signing identity from the configured path, which
/// reaches the keystore a second time. It is bound to the keystore the removal
/// was decided against, so a `keys` directory swapped in behind that path is
/// reported as a conflict and left exactly as it stands.
#[cfg(unix)]
#[test]
fn test_hand_over_is_refused_when_the_signing_identity_resolves_another_keystore_directory() {
    let (home, signer_kid) = signed_home();
    let _rotated_kid = rotate_active_key(home.path(), ALICE_MEMBER_HANDLE);
    copy_directory(
        &home.path().join("keys"),
        &home.path().join("keys.replacement"),
    );
    let options = build_options(home.path());

    let swap_home = home.path().to_path_buf();
    set_post_member_resolution_hook(move || swap_keystore_path(&swap_home));

    let error = remove_key_command(
        &options,
        None,
        signer_kid.clone(),
        false,
        |_member_handle| Ok(signing_execution(&home, None)),
    )
    .expect_err(
        "a hand-over must not re-sign through a keystore the removal never decided against",
    );

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert!(
        error
            .format_user_message()
            .contains("local keystore directory"),
        "{}",
        error.format_user_message()
    );
    let swapped = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .expect("the stored trust store must be untouched by the refused hand-over");
    assert_eq!(
        swapped.signer_kid.as_ref().map(Kid::as_str),
        Some(signer_kid.as_str())
    );
    assert!(key_dir(&home, &signer_kid).exists());
}

/// A hand-over signed by the key being removed would leave the stored
/// signature exactly where it was, so the removal is refused before anything is
/// written rather than reported as a successful hand-over.
#[test]
fn test_removal_stops_when_the_hand_over_leaves_the_signature_in_place() {
    let (home, signer_kid) = signed_home();
    let _rotated_kid = rotate_active_key(home.path(), ALICE_MEMBER_HANDLE);
    let options = build_options(home.path());

    let error = remove_key_command(
        &options,
        None,
        signer_kid.clone(),
        false,
        |_member_handle| Ok(signing_execution(&home, Some(&signer_kid))),
    )
    .expect_err("a signature that stayed on the removed key must stop the removal");

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert!(
        error.format_user_message().contains("cannot complete"),
        "{}",
        error.format_user_message()
    );
    assert!(key_dir(&home, &signer_kid).exists());
}

/// A deletion can still fail once the hand-over is committed: the advance check
/// releases its lock before the signature moves. The failure names the key that
/// took the signature over and the key that is still there, so the operator can
/// tell what the run left behind and finish it.
#[test]
fn test_a_deletion_that_failed_after_the_hand_over_names_both_keys() {
    let (home, signer_kid) = signed_home();
    let rotated_kid = rotate_active_key(home.path(), ALICE_MEMBER_HANDLE);
    let options = build_options(home.path());

    let error = remove_key_command(
        &options,
        None,
        signer_kid.clone(),
        false,
        |_member_handle| {
            // The advance check has passed by now, so this is what a concurrent
            // writer putting an undeletable entry into the key directory looks like.
            let kept = key_dir(&home, &signer_kid).join("nested");
            fs::create_dir(&kept).unwrap();
            fs::write(kept.join("kept.txt"), b"kept").unwrap();
            Ok(signing_execution(&home, None))
        },
    )
    .expect_err("a key directory holding an entry that cannot be deleted stops the removal");

    let message = error.format_user_message();
    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
    assert!(message.contains(rotated_kid.as_str()), "{message}");
    assert!(message.contains(&signer_kid), "{message}");
    assert!(
        message.contains(&format!(
            "kapsaro key remove {signer_kid} --member-handle {ALICE_MEMBER_HANDLE}"
        )),
        "{message}"
    );
    let stored = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .expect("the stored trust store must verify under the key that took the signature over");
    assert_eq!(
        stored.signer_kid.as_ref().map(Kid::as_str),
        Some(rotated_kid.as_str())
    );
    assert!(key_dir(&home, &signer_kid).exists());
}

/// The keystore settles whether the key can go before the signature is handed
/// over. A key directory holding an entry that cannot be deleted stops the
/// removal there, so the stored trust store is still signed by the key the
/// command was asked to remove rather than by the active one.
#[test]
fn test_a_removal_the_keystore_refuses_stops_before_the_hand_over() {
    let (home, signer_kid) = signed_home();
    let _rotated_kid = rotate_active_key(home.path(), ALICE_MEMBER_HANDLE);
    let kept = key_dir(&home, &signer_kid).join("nested");
    fs::create_dir(&kept).unwrap();
    fs::write(kept.join("kept.txt"), b"kept").unwrap();
    let options = build_options(home.path());

    let error = remove_key_command(
        &options,
        None,
        signer_kid.clone(),
        false,
        unreachable_handover,
    )
    .expect_err("a key directory holding an entry that cannot be deleted stops the removal");

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
    let stored = load_test_trust_store(&options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .expect("the stored trust store must be exactly as the removal found it");
    assert_eq!(
        stored.signer_kid.as_ref().map(Kid::as_str),
        Some(signer_kid.as_str())
    );
    assert!(key_dir(&home, &signer_kid).exists());
}
