// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Security tests for the anchored keystore access capability.
//! Covers validated directory names and fail-closed local-state traversal.

use super::{fail_next_key_pair_parent_sync, set_key_pair_staged_hook, KeystoreAccess};
use crate::app_test_utils::{
    build_test_private_key_document, build_test_public_key_document, TEST_KEY_SIGNATURE,
};
use crate::model::identity::{Kid, MemberHandle};
use crate::model::private_key::PrivateKey;
use crate::model::public_key::PublicKey;
use crate::support::warning::LocalStateWarningGuard;
use crate::test_utils::{
    create_local_state_dir, local_state_temp_dir, setup_test_keystore_from_fixtures,
    ALICE_MEMBER_HANDLE,
};
use crate::{Error, ErrorKind, Result};
use std::fs;
use std::sync::mpsc;
use std::time::Duration;
use tempfile::TempDir;

const LOCAL_STATE_PATH_UNSAFE: &str = "E_LOCAL_STATE_PATH_UNSAFE";

/// A name of the shape an unfinished directory write stages under.
const STAGING_DIR_NAME: &str = ".tmp-3f2504e0-4f89-41d3-9a0c-0305e82c3301";

fn assert_local_state_path_unsafe(error: &Error) {
    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some(LOCAL_STATE_PATH_UNSAFE));
}

/// The error a key pair reports when the rename published it but the directory
/// entry naming it was not persisted.
fn assert_unsynced_key_pair_error(error: &Error, kid: &Kid) {
    assert_eq!(error.kind(), ErrorKind::Io);
    let message = error.format_user_message();
    assert!(message.contains(kid.as_str()), "{message}");
    assert!(
        message.contains("was written, but its directory entry was not persisted"),
        "{message}"
    );
}

#[cfg(unix)]
use crate::config::resolution::global::create_home;
#[cfg(unix)]
use crate::io::keystore::paths::get_private_key_file_path_from_root;
#[cfg(unix)]
use crate::support::fs::test_umask::{isolated_umask_test, with_umask};
#[cfg(unix)]
use std::os::unix::fs::symlink;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// The temporary root under the name an ancestor finding carries.
///
/// The walk above an entry resolves each directory it names, so where the
/// temporary directory sits behind a symlink its findings carry the resolved
/// name and nothing else.
#[cfg(unix)]
fn resolved_root(temp: &TempDir) -> std::path::PathBuf {
    fs::canonicalize(temp.path()).expect("a temporary root resolves")
}

/// Keys under a directory another user can write are theirs to replace, so the
/// keystore names that directory while it opens.
#[cfg(unix)]
#[test]
fn test_keystore_access_open_from_home_warns_about_group_writable_ancestor() {
    let temp = local_state_temp_dir();
    let shared = temp.path().join("shared");
    create_local_state_dir(&shared.join("home").join("keys"));
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o770)).unwrap();

    let guard = LocalStateWarningGuard::new();
    KeystoreAccess::open_from_home(shared.join("home")).unwrap();

    let warning = guard.take_single_reason_under(&resolved_root(&temp));
    assert!(
        warning.contains("Insecure ancestor permissions 0770"),
        "{warning}"
    );
}

#[cfg(unix)]
#[test]
fn test_keystore_creation_warns_about_world_writable_ancestor() {
    let temp = local_state_temp_dir();
    let shared = temp.path().join("shared");
    create_local_state_dir(&shared);
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();

    let guard = LocalStateWarningGuard::new();
    let home = create_home(&shared.join("home")).unwrap();
    KeystoreAccess::create_from_anchored_home(&home).unwrap();

    let warning = guard.take_single_reason_under(&resolved_root(&temp));
    assert!(
        warning.contains("Insecure ancestor permissions 0777"),
        "{warning}"
    );
    assert!(shared.join("home").join("keys").is_dir());
}

/// The keystore is reached through the link, and the root it reports is the
/// path that was selected rather than the directory it resolved to.
#[cfg(unix)]
#[test]
fn test_keystore_access_open_from_home_opens_through_a_home_symlink() {
    let temp = local_state_temp_dir();
    let real_home = temp.path().join("real-home");
    let selected_home = temp.path().join("selected-home");
    fs::create_dir(&real_home).unwrap();
    fs::create_dir(real_home.join("keys")).unwrap();
    symlink(&real_home, &selected_home).unwrap();

    let access = KeystoreAccess::open_from_home(&selected_home).unwrap();

    assert_eq!(access.root(), selected_home.join("keys"));
    assert_eq!(access.list_members().unwrap(), Vec::<MemberHandle>::new());
}

#[cfg(unix)]
#[test]
fn test_keystore_access_open_from_home_allows_ancestor_symlink() {
    let temp = local_state_temp_dir();
    let real_parent = temp.path().join("real-parent");
    let linked_parent = temp.path().join("linked-parent");
    let home = real_parent.join("home");
    create_local_state_dir(&home.join("keys"));
    symlink(&real_parent, &linked_parent).unwrap();

    let access = KeystoreAccess::open_from_home(linked_parent.join("home")).unwrap();

    assert_eq!(access.list_members().unwrap(), Vec::<MemberHandle>::new());
}

#[cfg(unix)]
#[test]
fn test_keystore_access_open_from_home_retains_original_identity() {
    let temp = local_state_temp_dir();
    let home = temp.path().join("home");
    let original_home = temp.path().join("home.original");
    fs::create_dir(&home).unwrap();
    fs::create_dir(home.join("keys")).unwrap();
    let access = KeystoreAccess::open_from_home(&home).unwrap();
    fs::rename(&home, &original_home).unwrap();
    fs::create_dir(&home).unwrap();
    fs::create_dir(home.join("keys")).unwrap();
    fs::create_dir(home.join("keys/mallory@example.com")).unwrap();

    let members = access.list_members().unwrap();

    assert!(members.is_empty());
    assert!(home.join("keys/mallory@example.com").is_dir());
}

#[test]
fn test_keystore_access_lists_validated_member_handles() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    fs::create_dir(root.join("bob@example.com")).unwrap();
    fs::create_dir(root.join("alice@example.com")).unwrap();

    let members = access.list_members().unwrap();

    assert_eq!(
        members,
        vec![
            MemberHandle::try_from("alice@example.com").unwrap(),
            MemberHandle::try_from("bob@example.com").unwrap(),
        ]
    );
}

#[test]
fn test_keystore_access_list_members_ignores_unrelated_entries() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    fs::write(root.join(".DS_Store"), "metadata").unwrap();
    fs::create_dir(root.join("invalid member directory")).unwrap();
    fs::create_dir(root.join(ALICE_MEMBER_HANDLE)).unwrap();

    let members = access.list_members().unwrap();

    assert_eq!(
        members,
        vec![MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap()]
    );
}

#[test]
fn test_keystore_access_ignores_invalid_member_directory_name() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    fs::create_dir(root.join("invalid member")).unwrap();

    assert!(access.list_members().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn test_keystore_access_rejects_member_symlink() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let outside = temp.path().join("outside");
    let access = KeystoreAccess::create(&root).unwrap();
    fs::create_dir(&outside).unwrap();
    symlink(&outside, root.join("alice@example.com")).unwrap();
    let member = MemberHandle::try_from("alice@example.com").unwrap();

    let error = access.list_kids(&member).unwrap_err();

    assert_local_state_path_unsafe(&error);
}

#[test]
fn test_keystore_access_open_member_rejects_regular_file() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    fs::write(root.join(member.as_str()), "payload").unwrap();

    let error = access.list_kids(&member).unwrap_err();

    assert_local_state_path_unsafe(&error);
}

#[test]
fn test_keystore_access_active_roundtrip_uses_typed_identity() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    let member = MemberHandle::try_from("alice@example.com").unwrap();
    let kid = Kid::try_from("00000000000000000000000000000000").unwrap();

    access.set_active_kid_unchecked(&member, &kid).unwrap();

    assert_eq!(access.load_active_kid(&member).unwrap(), Some(kid));
}

#[test]
fn test_keystore_access_active_load_ignores_unrelated_hidden_directory() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = Kid::try_from("00000000000000000000000000000000").unwrap();
    access.set_active_kid_unchecked(&member, &kid).unwrap();
    fs::create_dir(root.join(member.as_str()).join(".tmp-stale")).unwrap();

    assert_eq!(access.load_active_kid(&member).unwrap(), Some(kid));
}

#[test]
fn test_keystore_access_active_load_ignores_unexpected_sibling() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = Kid::try_from("00000000000000000000000000000000").unwrap();
    access.set_active_kid_unchecked(&member, &kid).unwrap();
    fs::write(root.join(member.as_str()).join("unexpected"), "payload").unwrap();

    assert_eq!(access.load_active_kid(&member).unwrap(), Some(kid));
}

#[test]
fn test_keystore_access_active_load_ignores_unrelated_entries() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = Kid::try_from("00000000000000000000000000000000").unwrap();
    access.set_active_kid_unchecked(&member, &kid).unwrap();
    fs::write(root.join(member.as_str()).join(".DS_Store"), "metadata").unwrap();
    fs::create_dir(root.join(member.as_str()).join(".tmp-stale")).unwrap();

    assert_eq!(access.load_active_kid(&member).unwrap(), Some(kid));
}

#[test]
fn test_keystore_access_public_key_load_ignores_unrelated_hidden_directory() {
    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let access = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = access.load_active_kid(&member).unwrap().unwrap();
    fs::create_dir(access.root().join(member.as_str()).join(".tmp-stale")).unwrap();

    let public_key = access.load_public_key(&member, &kid).unwrap();

    assert_eq!(public_key.protected.kid, kid.as_str());
}

#[test]
fn test_keystore_access_private_key_load_ignores_unexpected_sibling() {
    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let access = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = access.load_active_kid(&member).unwrap().unwrap();
    fs::write(
        access.root().join(member.as_str()).join("unexpected"),
        "payload",
    )
    .unwrap();

    let private_key = access.load_private_key(&member, &kid).unwrap();

    assert_eq!(private_key.protected.kid, kid.as_str());
}

#[test]
fn test_keystore_access_key_activation_ignores_unrelated_hidden_file() {
    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let access = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = access.load_active_kid(&member).unwrap().unwrap();
    fs::write(
        access.root().join(member.as_str()).join(".tmp-stale"),
        "payload",
    )
    .unwrap();

    access.activate_existing_key(&member, &kid).unwrap();

    assert_eq!(access.load_active_kid(&member).unwrap(), Some(kid));
}

/// Activation reads the private half to settle that the key can be signed with,
/// and a private key another account can already reach is handed to nobody. The
/// refusal is what carries the exposure here: naming it as a warning and moving
/// the marker anyway would leave the member pointed at a key every later command
/// refuses, and the operator told about it only in passing.
#[cfg(unix)]
#[test]
fn test_keystore_access_key_activation_refuses_an_exposed_private_key() {
    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let access = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = access.load_active_kid(&member).unwrap().unwrap();
    let private_path = access
        .root()
        .join(member.as_str())
        .join(kid.as_str())
        .join("private.json");
    fs::set_permissions(&private_path, fs::Permissions::from_mode(0o644)).unwrap();

    let _guard = LocalStateWarningGuard::new();
    let error = access.activate_existing_key(&member, &kid).unwrap_err();

    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PRIVATE_KEY_EXPOSED"));
    let message = error.format_user_message();
    assert!(message.contains("Insecure permissions 0644"), "{message}");
    assert!(message.contains("expected 0600"), "{message}");
    assert!(message.contains("chmod 0600"), "{message}");
}

/// A key directory with one of its two documents gone is named as that, and the
/// mode that lets others reach it is reported alongside the refusal.
#[cfg(unix)]
#[test]
fn test_keystore_access_key_activation_warns_about_insecure_key_directory_permissions() {
    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let access = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = access.load_active_kid(&member).unwrap().unwrap();
    let key_dir = access.root().join(member.as_str()).join(kid.as_str());
    fs::remove_file(key_dir.join("private.json")).unwrap();
    fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o755)).unwrap();

    let guard = LocalStateWarningGuard::new();
    let error = access.activate_existing_key(&member, &kid).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert!(
        error
            .format_user_message()
            .contains("missing one of the two key documents"),
        "{error}"
    );
    let warning = guard.take_single_reason_under(fixture.path());
    assert!(warning.contains("Insecure permissions 0755"), "{warning}");
}

#[test]
fn test_keystore_access_public_key_load_waits_for_key_pair_publication() {
    assert_key_reader_waits_for_publication(KeyReadOperation::Public);
}

#[test]
fn test_keystore_access_private_key_load_waits_for_key_pair_publication() {
    assert_key_reader_waits_for_publication(KeyReadOperation::Private);
}

#[test]
fn test_keystore_access_list_kids_waits_for_key_pair_publication() {
    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let source = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = source.load_active_kid(&member).unwrap().unwrap();
    let private_key = source.load_private_key(&member, &kid).unwrap();
    let public_key = source.load_public_key(&member, &kid).unwrap();
    let target = local_state_temp_dir();
    #[cfg(unix)]
    set_owner_only(&target);
    let writer = KeystoreAccess::create(target.path().join("keys")).unwrap();
    let reader = KeystoreAccess::open(target.path().join("keys")).unwrap();
    let (staged_tx, staged_rx) = mpsc::channel();
    let (publish_tx, publish_rx) = mpsc::channel();

    let writer_member = member.clone();
    let writer_kid = kid.clone();
    let writer_thread = std::thread::spawn(move || {
        set_key_pair_staged_hook(move || {
            staged_tx.send(()).unwrap();
            publish_rx.recv().unwrap();
        });
        writer.save_key_pair_atomic(&writer_member, &writer_kid, &private_key, &public_key)
    });
    staged_rx.recv_timeout(Duration::from_secs(2)).unwrap();

    let reader_member = member.clone();
    let (reader_thread, listed_rx) = spawn_started_reader(move || reader.list_kids(&reader_member));
    assert!(listed_rx.recv_timeout(Duration::from_millis(100)).is_err());

    publish_tx.send(()).unwrap();
    writer_thread.join().unwrap().unwrap();
    assert_eq!(
        listed_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap(),
        vec![kid]
    );
    reader_thread.join().unwrap();
}

#[test]
fn test_keystore_access_list_kids_waits_for_active_publication() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let writer = KeystoreAccess::create(&root).unwrap();
    let reader = KeystoreAccess::open(&root).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = Kid::try_from("00000000000000000000000000000000").unwrap();
    let (staged_tx, staged_rx) = mpsc::channel();
    let (publish_tx, publish_rx) = mpsc::channel();

    let writer_member = member.clone();
    let writer_kid = kid.clone();
    let writer_thread = std::thread::spawn(move || {
        writer.set_active_kid_with_staging_hook(&writer_member, &writer_kid, || {
            staged_tx.send(()).unwrap();
            publish_rx.recv().unwrap();
        })
    });
    staged_rx.recv_timeout(Duration::from_secs(2)).unwrap();

    let reader_member = member.clone();
    let (reader_thread, listed_rx) = spawn_started_reader(move || reader.list_kids(&reader_member));
    assert!(listed_rx.recv_timeout(Duration::from_millis(100)).is_err());

    publish_tx.send(()).unwrap();
    writer_thread.join().unwrap().unwrap();
    assert_eq!(
        listed_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap(),
        Vec::<Kid>::new()
    );
    reader_thread.join().unwrap();
}

#[test]
fn test_keystore_access_active_load_waits_for_active_publication() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let writer = KeystoreAccess::create(&root).unwrap();
    let reader = KeystoreAccess::open(&root).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let old_kid = Kid::try_from("00000000000000000000000000000000").unwrap();
    let new_kid = Kid::try_from("00000000000000000000000000000001").unwrap();
    writer.set_active_kid_unchecked(&member, &old_kid).unwrap();
    let (staged_tx, staged_rx) = mpsc::channel();
    let (publish_tx, publish_rx) = mpsc::channel();

    let writer_member = member.clone();
    let writer_thread = std::thread::spawn(move || {
        writer.set_active_kid_with_staging_hook(&writer_member, &new_kid, || {
            staged_tx.send(()).unwrap();
            publish_rx.recv().unwrap();
        })
    });
    staged_rx.recv_timeout(Duration::from_secs(2)).unwrap();

    let reader_member = member.clone();
    let (reader_thread, loaded_rx) =
        spawn_started_reader(move || reader.load_active_kid(&reader_member));
    assert!(loaded_rx.recv_timeout(Duration::from_millis(100)).is_err());

    publish_tx.send(()).unwrap();
    writer_thread.join().unwrap().unwrap();
    assert_eq!(
        loaded_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap(),
        Some(Kid::try_from("00000000000000000000000000000001").unwrap())
    );
    reader_thread.join().unwrap();
}

#[test]
fn test_keystore_access_force_remove_then_activate_preserves_new_active() {
    let (temp, remover, activator, member, removed_kid, activated_kid) =
        setup_key_transaction_access();
    remover
        .set_active_kid_unchecked(&member, &removed_kid)
        .unwrap();
    let (checked_tx, checked_rx) = mpsc::channel();
    let (continue_tx, continue_rx) = mpsc::channel();

    let remove_member = member.clone();
    let remove_thread = std::thread::spawn(move || {
        remover.remove_key_with_validation(&remove_member, &removed_kid, |was_active| {
            assert!(was_active);
            checked_tx.send(()).unwrap();
            continue_rx.recv().unwrap();
            Ok(())
        })
    });
    checked_rx.recv_timeout(Duration::from_secs(2)).unwrap();

    let activate_member = member.clone();
    let expected_active = activated_kid.clone();
    let (activated_tx, activated_rx) = mpsc::channel();
    let activate_thread = std::thread::spawn(move || {
        activated_tx
            .send(activator.activate_existing_key(&activate_member, &activated_kid))
            .unwrap();
    });
    assert!(activated_rx
        .recv_timeout(Duration::from_millis(100))
        .is_err());

    continue_tx.send(()).unwrap();
    assert!(remove_thread.join().unwrap().unwrap());
    activated_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap();
    activate_thread.join().unwrap();

    let access = KeystoreAccess::open(temp.path().join("keys")).unwrap();
    assert_eq!(
        access.load_active_kid(&member).unwrap(),
        Some(expected_active)
    );
}

#[test]
fn test_keystore_access_remove_then_same_key_activate_not_found() {
    let (temp, remover, activator, member, removed_kid, _) = setup_key_transaction_access();
    remover
        .set_active_kid_unchecked(&member, &removed_kid)
        .unwrap();
    let (checked_tx, checked_rx) = mpsc::channel();
    let (continue_tx, continue_rx) = mpsc::channel();

    let remove_member = member.clone();
    let activate_kid = removed_kid.clone();
    let remove_thread = std::thread::spawn(move || {
        remover.remove_key_with_validation(&remove_member, &removed_kid, |was_active| {
            assert!(was_active);
            checked_tx.send(()).unwrap();
            continue_rx.recv().unwrap();
            Ok(())
        })
    });
    checked_rx.recv_timeout(Duration::from_secs(2)).unwrap();

    let activate_member = member.clone();
    let (activated_tx, activated_rx) = mpsc::channel();
    let activate_thread = std::thread::spawn(move || {
        activated_tx
            .send(activator.activate_existing_key(&activate_member, &activate_kid))
            .unwrap();
    });
    assert!(activated_rx
        .recv_timeout(Duration::from_millis(100))
        .is_err());

    continue_tx.send(()).unwrap();
    assert!(remove_thread.join().unwrap().unwrap());
    let error = activated_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap_err();
    activate_thread.join().unwrap();

    assert_eq!(error.kind(), ErrorKind::NotFound);
    assert_eq!(
        KeystoreAccess::open(temp.path().join("keys"))
            .unwrap()
            .load_active_kid(&member)
            .unwrap(),
        None
    );
}

#[test]
fn test_keystore_access_list_kids_ignores_unrelated_hidden_directory() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    create_local_state_dir(&root.join(member.as_str()).join(".tmp-stale"));

    assert!(access.list_kids(&member).unwrap().is_empty());
}

#[test]
fn test_keystore_access_mutation_ignores_unrelated_hidden_directory() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = Kid::try_from("00000000000000000000000000000000").unwrap();
    create_local_state_dir(&root.join(member.as_str()).join(".tmp-stale"));

    access.set_active_kid_unchecked(&member, &kid).unwrap();

    assert_eq!(access.load_active_kid(&member).unwrap(), Some(kid));
}

#[test]
fn test_keystore_access_mutation_ignores_unrelated_entry_left_at_unlock() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = Kid::try_from("00000000000000000000000000000000").unwrap();
    let stale = root.join(member.as_str()).join(".tmp-left-behind");

    access
        .set_active_kid_with_staging_hook(&member, &kid, || fs::create_dir(&stale).unwrap())
        .unwrap();

    assert_eq!(access.load_active_kid(&member).unwrap(), Some(kid));
    assert!(stale.exists());
}

/// A namespace that turns unsafe while the write is in flight is reported for
/// what it is: the document is already on disk, so the message says so rather
/// than reading as a failed write.
#[test]
fn test_keystore_access_mutation_reports_a_namespace_that_became_unsafe_after_the_write() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = Kid::try_from("00000000000000000000000000000000").unwrap();
    let residue = root.join(member.as_str()).join(STAGING_DIR_NAME);

    let error = access
        .set_active_kid_with_staging_hook(&member, &kid, || fs::create_dir(&residue).unwrap())
        .unwrap_err();

    assert_local_state_path_unsafe(&error);
    let message = error.format_user_message();
    assert!(message.contains("was written, but"), "{message}");
    assert_eq!(
        fs::read_to_string(root.join(member.as_str()).join("active")).unwrap(),
        format!("{}\n", kid.as_str())
    );
}

/// The failure the caller asked about is the write's own. A namespace that also
/// looks wrong once the write is over must not take its place.
#[test]
fn test_keystore_access_mutation_failure_survives_a_later_namespace_failure() {
    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let source = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = source.load_active_kid(&member).unwrap().unwrap();
    let private_key = source.load_private_key(&member, &kid).unwrap();
    let public_key = source.load_public_key(&member, &kid).unwrap();
    let target = local_state_temp_dir();
    #[cfg(unix)]
    set_owner_only(&target);
    let access = KeystoreAccess::create(target.path().join("keys")).unwrap();
    let residue = access.root().join(member.as_str()).join(STAGING_DIR_NAME);

    fail_next_key_pair_parent_sync();
    set_key_pair_staged_hook(move || fs::create_dir(&residue).unwrap());
    let error = access
        .save_key_pair_atomic(&member, &kid, &private_key, &public_key)
        .unwrap_err();

    assert_unsynced_key_pair_error(&error, &kid);
}

#[cfg(unix)]
#[test]
fn test_keystore_access_key_pair_save_member_symlink_external_target_error() {
    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let source = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = source.load_active_kid(&member).unwrap().unwrap();
    let private_key = source.load_private_key(&member, &kid).unwrap();
    let public_key = source.load_public_key(&member, &kid).unwrap();

    let target = local_state_temp_dir();
    let outside = target.path().join("outside");
    let access = KeystoreAccess::create(target.path().join("keys")).unwrap();
    fs::create_dir(&outside).unwrap();
    symlink(&outside, access.root().join(member.as_str())).unwrap();

    let error = access
        .save_key_pair_atomic(&member, &kid, &private_key, &public_key)
        .unwrap_err();

    assert_local_state_path_unsafe(&error);
    assert!(fs::read_dir(&outside).unwrap().next().is_none());
}

#[cfg(unix)]
#[test]
fn test_keystore_access_key_remove_kid_symlink_external_target_error() {
    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let access = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = access.load_active_kid(&member).unwrap().unwrap();
    let key_path = access.root().join(member.as_str()).join(kid.as_str());
    let original_path = access
        .root()
        .join(member.as_str())
        .join(format!("{}.real", kid.as_str()));
    let outside = fixture.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("marker"), "outside").unwrap();
    fs::rename(&key_path, &original_path).unwrap();
    symlink(&outside, &key_path).unwrap();

    let error = access
        .remove_key_with_validation(&member, &kid, |_| Ok(()))
        .unwrap_err();

    assert_local_state_path_unsafe(&error);
    assert_eq!(
        fs::read_to_string(outside.join("marker")).unwrap(),
        "outside"
    );
    assert!(original_path.join("private.json").exists());
}

isolated_umask_test! {
    /// Every directory the keystore creates on the way to a missing home is
    /// owner only, whatever the process umask would otherwise have allowed.
    #[cfg(unix)]
    fn test_keystore_access_create_restricts_the_directories_it_creates() {
        let target = local_state_temp_dir();
        let home = target.path().join("missing/home");
        let root = home.join("keys");

        with_umask(0o022, || {
            KeystoreAccess::create(&root).unwrap();
        });

        assert_mode(&home, 0o700);
        assert_mode(&root, 0o700);
    }
}

isolated_umask_test! {
    /// A saved key pair is owner only down to the private key itself: the key
    /// directory keeps others out, and the document is unreadable to them even
    /// if they reach it.
    #[cfg(unix)]
    fn test_keystore_access_save_key_pair_restricts_the_saved_private_key() {
        let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
        let source = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
        let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
        let kid = source.load_active_kid(&member).unwrap().unwrap();
        let private_key = source.load_private_key(&member, &kid).unwrap();
        let public_key = source.load_public_key(&member, &kid).unwrap();
        let target = local_state_temp_dir();
        let root = target.path().join("missing/home/keys");

        with_umask(0o022, || {
            let access = KeystoreAccess::create(&root).unwrap();
            access
                .save_key_pair_atomic(&member, &kid, &private_key, &public_key)
                .unwrap();
            assert_eq!(access.load_private_key(&member, &kid).unwrap(), private_key);
        });

        let private_key_path = get_private_key_file_path_from_root(&root, &member, &kid);
        assert_mode(private_key_path.parent().unwrap(), 0o700);
        assert_mode(&private_key_path, 0o600);
    }
}

#[cfg(unix)]
fn assert_mode(path: &std::path::Path, expected: u32) {
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        expected,
        "unexpected mode on {}",
        path.display()
    );
}

/// A group-readable local state home is named while the keystore is created
/// under it, and its mode is left for the operator to repair.
#[cfg(unix)]
#[test]
fn test_keystore_creation_warns_about_insecure_home_permissions() {
    let temp = local_state_temp_dir();
    let home = temp.path().join("shared-home");
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o750)).unwrap();

    let guard = LocalStateWarningGuard::new();
    let opened = create_home(&home).unwrap();
    KeystoreAccess::create_from_anchored_home(&opened).unwrap();

    let warning = guard.take_single_reason_under(temp.path());
    assert!(warning.contains("Insecure permissions 0750"), "{warning}");
    assert!(warning.contains("expected 0700"), "{warning}");
    assert!(warning.contains("chmod 0700"), "{warning}");
    assert!(home.join("keys").is_dir());
    assert_mode(&home, 0o750);
}

#[test]
fn test_keystore_access_parent_sync_failure_preserves_published_key_pair() {
    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let source = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = source.load_active_kid(&member).unwrap().unwrap();
    let private_key = source.load_private_key(&member, &kid).unwrap();
    let public_key = source.load_public_key(&member, &kid).unwrap();
    let target = local_state_temp_dir();
    #[cfg(unix)]
    set_owner_only(&target);
    let access = KeystoreAccess::create(target.path().join("keys")).unwrap();

    fail_next_key_pair_parent_sync();

    let error = access
        .save_key_pair_atomic(&member, &kid, &private_key, &public_key)
        .unwrap_err();

    assert_unsynced_key_pair_error(&error, &kid);
    assert_eq!(access.load_private_key(&member, &kid).unwrap(), private_key);
    assert_eq!(access.load_public_key(&member, &kid).unwrap(), public_key);
    assert!(!member_dir_has_temp_entry(&access, &member));

    let retry_error = access
        .save_key_pair_atomic(&member, &kid, &private_key, &public_key)
        .unwrap_err();
    assert_local_state_path_unsafe(&retry_error);
    assert_eq!(access.load_private_key(&member, &kid).unwrap(), private_key);
    assert_eq!(access.load_public_key(&member, &kid).unwrap(), public_key);
    assert!(!member_dir_has_temp_entry(&access, &member));
}

#[test]
fn test_keystore_access_rename_failure_removes_temporary_key_pair() {
    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let source = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = source.load_active_kid(&member).unwrap().unwrap();
    let private_key = source.load_private_key(&member, &kid).unwrap();
    let public_key = source.load_public_key(&member, &kid).unwrap();
    let target = local_state_temp_dir();
    #[cfg(unix)]
    set_owner_only(&target);
    let access = KeystoreAccess::create(target.path().join("keys")).unwrap();
    access
        .save_key_pair_atomic(&member, &kid, &private_key, &public_key)
        .unwrap();

    let error = access
        .save_key_pair_atomic(&member, &kid, &private_key, &public_key)
        .unwrap_err();

    assert_local_state_path_unsafe(&error);
    assert_eq!(access.load_private_key(&member, &kid).unwrap(), private_key);
    assert_eq!(access.load_public_key(&member, &kid).unwrap(), public_key);
    assert!(!member_dir_has_temp_entry(&access, &member));
}

#[test]
fn test_keystore_access_list_members_ignores_unexpected_root_file() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    fs::write(root.join("unexpected"), "payload").unwrap();
    fs::create_dir(root.join(ALICE_MEMBER_HANDLE)).unwrap();

    let members = access.list_members().unwrap();

    assert_eq!(
        members,
        vec![MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap()]
    );
}

/// A regular file wearing a kid name stands where a key directory belongs, so
/// the member namespace holding it is refused rather than enumerated.
#[test]
fn test_keystore_access_rejects_kid_named_regular_file_in_member_directory() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let stored_kid = Kid::try_from("00000000000000000000000000000000").unwrap();
    let file_kid = Kid::try_from("11111111111111111111111111111111").unwrap();
    fs::create_dir_all(root.join(member.as_str()).join(stored_kid.as_str())).unwrap();
    fs::write(
        root.join(member.as_str()).join(file_kid.as_str()),
        "payload",
    )
    .unwrap();

    let error = access.list_kids(&member).unwrap_err();

    assert_local_state_path_unsafe(&error);
}

/// A symlink wearing a kid name would hand out whatever it points at as that
/// key, so it is refused instead of skipped.
#[cfg(unix)]
#[test]
fn test_keystore_access_rejects_kid_named_symlink_in_member_directory() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = Kid::try_from("00000000000000000000000000000000").unwrap();
    let outside = temp.path().join("outside");
    fs::create_dir_all(root.join(member.as_str())).unwrap();
    fs::create_dir(&outside).unwrap();
    symlink(&outside, root.join(member.as_str()).join(kid.as_str())).unwrap();

    let error = access.list_kids(&member).unwrap_err();

    assert_local_state_path_unsafe(&error);
}

/// A member handle looks like any other file name, so the root cannot tell one
/// from a name the keystore never wrote until a caller asks for that member.
/// Asking is where a file standing in the member's place is refused.
#[test]
fn test_keystore_access_refuses_a_named_member_held_by_a_regular_file() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    fs::write(root.join(ALICE_MEMBER_HANDLE), "payload").unwrap();

    let error = access.list_kids(&member).unwrap_err();

    assert_local_state_path_unsafe(&error);
}

#[cfg(unix)]
#[test]
fn test_keystore_access_refuses_a_named_member_held_by_a_symlink() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let outside = temp.path().join("outside");
    let access = KeystoreAccess::create(&root).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    fs::create_dir(&outside).unwrap();
    symlink(&outside, root.join(ALICE_MEMBER_HANDLE)).unwrap();

    let error = access.list_kids(&member).unwrap_err();

    assert_local_state_path_unsafe(&error);
}

#[test]
fn test_keystore_access_load_optional_public_key_missing_member_returns_none() {
    let temp = local_state_temp_dir();
    let access = KeystoreAccess::create(temp.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = Kid::try_from("00000000000000000000000000000000").unwrap();

    let public_key = access.load_optional_public_key(&member, &kid).unwrap();

    assert!(public_key.is_none());
}

#[test]
fn test_keystore_access_load_optional_public_key_missing_kid_returns_none() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = Kid::try_from("00000000000000000000000000000000").unwrap();
    fs::create_dir(root.join(member.as_str())).unwrap();

    let public_key = access.load_optional_public_key(&member, &kid).unwrap();

    assert!(public_key.is_none());
}

#[test]
fn test_keystore_access_load_optional_public_key_missing_document_returns_none() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = Kid::try_from("00000000000000000000000000000000").unwrap();
    fs::create_dir_all(root.join(member.as_str()).join(kid.as_str())).unwrap();

    let public_key = access.load_optional_public_key(&member, &kid).unwrap();

    assert!(public_key.is_none());
}

#[cfg(all(unix, not(target_vendor = "apple")))]
#[test]
fn test_keystore_access_rejects_non_utf8_entry_name() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    fs::write(root.join(OsString::from_vec(vec![0xff])), "payload").unwrap();

    let error = access.list_members().unwrap_err();

    assert_local_state_path_unsafe(&error);
}

/// A directory standing where the `active` marker belongs is refused before the
/// write is attempted, and survives that refusal intact.
#[test]
fn test_keystore_access_rejects_active_named_directory_in_member_directory() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    let member = MemberHandle::try_from("alice@example.com").unwrap();
    let kid = Kid::try_from("00000000000000000000000000000000").unwrap();
    let active_path = root.join(member.as_str()).join("active");
    fs::create_dir_all(&active_path).unwrap();

    let error = access.set_active_kid_unchecked(&member, &kid).unwrap_err();

    assert_local_state_path_unsafe(&error);
    assert!(active_path.is_dir());
}

/// An entry named like an unpublished staging write inside a member directory is
/// the trace of an interrupted write, so the namespace is refused.
#[test]
fn test_keystore_access_rejects_leftover_staging_entry_in_member_directory() {
    let temp = local_state_temp_dir();
    let root = temp.path().join("keys");
    let access = KeystoreAccess::create(&root).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    create_local_state_dir(&root.join(member.as_str()).join(STAGING_DIR_NAME));

    let error = access.list_kids(&member).unwrap_err();

    assert_local_state_path_unsafe(&error);
}

/// A key document name taken by a directory or a symlink shadows the document
/// the keystore wrote, so the key is not handed out.
#[test]
fn test_keystore_access_rejects_key_document_named_directory_in_key_directory() {
    for shadowed in ["private.json", "public.json"] {
        let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
        let access = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
        let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
        let kid = access.load_active_kid(&member).unwrap().unwrap();
        let key_dir = access.root().join(member.as_str()).join(kid.as_str());
        fs::remove_file(key_dir.join(shadowed)).unwrap();
        fs::create_dir(key_dir.join(shadowed)).unwrap();

        let error = access.load_public_key(&member, &kid).unwrap_err();

        assert_local_state_path_unsafe(&error);
    }
}

#[cfg(unix)]
#[test]
fn test_keystore_access_rejects_key_document_named_symlink_in_key_directory() {
    for shadowed in ["private.json", "public.json"] {
        let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
        let access = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
        let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
        let kid = access.load_active_kid(&member).unwrap().unwrap();
        let key_dir = access.root().join(member.as_str()).join(kid.as_str());
        let outside = fixture.path().join("outside");
        fs::write(&outside, "outside").unwrap();
        fs::remove_file(key_dir.join(shadowed)).unwrap();
        symlink(&outside, key_dir.join(shadowed)).unwrap();

        let error = access.load_public_key(&member, &kid).unwrap_err();

        assert_local_state_path_unsafe(&error);
    }
}

#[cfg(unix)]
#[test]
fn test_keystore_access_rejects_special_public_key_file() {
    use std::process::Command;

    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let access = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = access.load_active_kid(&member).unwrap().unwrap();
    let public_path = access
        .root()
        .join(member.as_str())
        .join(kid.as_str())
        .join("public.json");
    fs::remove_file(&public_path).unwrap();
    assert!(Command::new("mkfifo")
        .arg(&public_path)
        .status()
        .unwrap()
        .success());

    let error = access.load_public_key(&member, &kid).unwrap_err();

    assert_local_state_path_unsafe(&error);
}

#[derive(Clone, Copy)]
enum KeyReadOperation {
    Public,
    Private,
}

/// One half of a key pair, as the thread that read it hands it back.
#[derive(Debug, PartialEq)]
enum LoadedKey {
    Public(PublicKey),
    Private(PrivateKey),
}

impl KeyReadOperation {
    fn load(self, access: &KeystoreAccess, member: &MemberHandle, kid: &Kid) -> Result<LoadedKey> {
        match self {
            Self::Public => access.load_public_key(member, kid).map(LoadedKey::Public),
            Self::Private => access.load_private_key(member, kid).map(LoadedKey::Private),
        }
    }

    /// The document this operation has to hand back once the write publishes.
    fn expect_loaded(self, private_key: &PrivateKey, public_key: &PublicKey) -> LoadedKey {
        match self {
            Self::Public => LoadedKey::Public(public_key.clone()),
            Self::Private => LoadedKey::Private(private_key.clone()),
        }
    }
}

/// Run `read` on its own thread, returning once that thread has begun.
///
/// A caller that then watches the read stay unanswered is watching it wait on
/// the keystore lock, rather than on the thread being scheduled at all.
fn spawn_started_reader<T, F>(read: F) -> (std::thread::JoinHandle<()>, mpsc::Receiver<T>)
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (started_tx, started_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        result_tx.send(read()).unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    (handle, result_rx)
}

fn assert_key_reader_waits_for_publication(operation: KeyReadOperation) {
    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let source = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = source.load_active_kid(&member).unwrap().unwrap();
    let private_key = source.load_private_key(&member, &kid).unwrap();
    let public_key = source.load_public_key(&member, &kid).unwrap();
    let expected = operation.expect_loaded(&private_key, &public_key);
    let target = local_state_temp_dir();
    #[cfg(unix)]
    set_owner_only(&target);
    let writer = KeystoreAccess::create(target.path().join("keys")).unwrap();
    let reader = KeystoreAccess::open(target.path().join("keys")).unwrap();
    let (staged_tx, staged_rx) = mpsc::channel();
    let (publish_tx, publish_rx) = mpsc::channel();

    let writer_member = member.clone();
    let writer_kid = kid.clone();
    let writer_thread = std::thread::spawn(move || {
        set_key_pair_staged_hook(move || {
            staged_tx.send(()).unwrap();
            publish_rx.recv().unwrap();
        });
        writer.save_key_pair_atomic(&writer_member, &writer_kid, &private_key, &public_key)
    });
    staged_rx.recv_timeout(Duration::from_secs(2)).unwrap();

    let (reader_thread, loaded_rx) =
        spawn_started_reader(move || operation.load(&reader, &member, &kid));
    assert!(loaded_rx.recv_timeout(Duration::from_millis(100)).is_err());

    publish_tx.send(()).unwrap();
    writer_thread.join().unwrap().unwrap();
    let loaded = loaded_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(loaded.unwrap(), expected);
    reader_thread.join().unwrap();
}

fn member_dir_has_temp_entry(access: &KeystoreAccess, member: &MemberHandle) -> bool {
    fs::read_dir(access.root().join(member.as_str()))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .any(|name| name.to_string_lossy().starts_with(".tmp-"))
}

fn setup_key_transaction_access() -> (
    TempDir,
    KeystoreAccess,
    KeystoreAccess,
    MemberHandle,
    Kid,
    Kid,
) {
    let temp = local_state_temp_dir();
    #[cfg(unix)]
    set_owner_only(&temp);
    let root = temp.path().join("keys");
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let first = Kid::try_from("00000000000000000000000000000000").unwrap();
    let second = Kid::try_from("00000000000000000000000000000001").unwrap();
    for kid in [&first, &second] {
        let key_dir = root.join(member.as_str()).join(kid.as_str());
        fs::create_dir_all(&key_dir).unwrap();
        // Activation reads both halves to settle that the key is complete,
        // states the member and key its directory names, and has not expired,
        // so each stored document has to be one it can parse.
        fs::write(
            key_dir.join("private.json"),
            serde_json::to_string_pretty(&build_test_private_key_document(
                member.as_str(),
                kid.as_str(),
            ))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            key_dir.join("public.json"),
            serde_json::to_string_pretty(&build_test_public_key_document(
                member.as_str(),
                kid.as_str(),
                TEST_KEY_SIGNATURE,
            ))
            .unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            set_path_owner_only(&root);
            set_path_owner_only(&root.join(member.as_str()));
            set_path_owner_only(&key_dir);
            fs::set_permissions(
                key_dir.join("private.json"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
    }
    let remover = KeystoreAccess::open(&root).unwrap();
    let activator = KeystoreAccess::open(&root).unwrap();
    (temp, remover, activator, member, first, second)
}

#[cfg(unix)]
fn set_owner_only(directory: &TempDir) {
    set_path_owner_only(directory.path());
}

#[cfg(unix)]
fn set_path_owner_only(path: &std::path::Path) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn test_keystore_access_key_load_ignores_unrelated_key_directory_entries() {
    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let access = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = access.load_active_kid(&member).unwrap().unwrap();
    let key_dir = access.root().join(member.as_str()).join(kid.as_str());
    fs::write(key_dir.join(".DS_Store"), "metadata").unwrap();
    fs::write(key_dir.join("public.json.swp"), "editor swap").unwrap();
    fs::create_dir(key_dir.join(".tmp-stale")).unwrap();

    assert_eq!(
        access
            .load_private_key(&member, &kid)
            .unwrap()
            .protected
            .kid,
        kid.as_str()
    );
    assert_eq!(
        access.load_public_key(&member, &kid).unwrap().protected.kid,
        kid.as_str()
    );
    assert_eq!(access.list_kids(&member).unwrap(), vec![kid.clone()]);
    assert_eq!(access.resolve_kid(&member, None).unwrap(), kid);
}

#[test]
fn test_keystore_access_key_removal_clears_unrelated_key_directory_entries() {
    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let access = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = access.load_active_kid(&member).unwrap().unwrap();
    let key_dir = access.root().join(member.as_str()).join(kid.as_str());
    fs::write(key_dir.join(".DS_Store"), "metadata").unwrap();

    let was_active = access
        .remove_key_with_validation(&member, &kid, |_| Ok(()))
        .unwrap();

    assert!(was_active);
    assert!(!key_dir.exists());
}

#[cfg(unix)]
#[test]
/// A symlink is never one of the key documents, so it neither blocks the key
/// nor is followed on the way to it.
fn test_keystore_access_ignores_symlink_inside_key_directory() {
    use std::os::unix::fs::symlink;

    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let access = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = access.load_active_kid(&member).unwrap().unwrap();
    let key_dir = access.root().join(member.as_str()).join(kid.as_str());
    let outside = fixture.path().join("outside");
    fs::write(&outside, "outside").unwrap();
    symlink(&outside, key_dir.join("linked.json")).unwrap();

    let public_key = access.load_public_key(&member, &kid).unwrap();

    assert_eq!(public_key.protected.kid, kid.as_str());
    assert_eq!(fs::read_to_string(&outside).unwrap(), "outside");
}

/// A staging directory is abandoned only when the publish rename fails, and it
/// can hold more than the two key documents by then. Cleanup must still leave
/// the member namespace empty.
#[test]
fn test_abandoned_key_staging_directory_is_removed_with_all_of_its_entries() {
    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let source = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = source.load_active_kid(&member).unwrap().unwrap();
    let private_key = source.load_private_key(&member, &kid).unwrap();
    let public_key = source.load_public_key(&member, &kid).unwrap();

    let target = local_state_temp_dir();
    let keystore_root = target.path().join("keys");
    let writer = KeystoreAccess::create(&keystore_root).unwrap();
    let member_dir = keystore_root.join(member.as_str());

    let staging_dir = member_dir.clone();
    let staging_kid = kid.clone();
    set_key_pair_staged_hook(move || {
        let staging = find_staging_directory(&staging_dir);
        fs::write(staging.join("leftover.tmp"), "partial").unwrap();
        // Occupy the publish target so the no-replace rename fails.
        fs::create_dir(staging_dir.join(staging_kid.as_str())).unwrap();
    });
    let error = writer
        .save_key_pair_atomic(&member, &kid, &private_key, &public_key)
        .expect_err("publishing onto an existing key directory must fail");

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    let leftovers = fs::read_dir(&member_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".tmp-"))
        .collect::<Vec<_>>();
    assert!(leftovers.is_empty(), "staging left behind: {leftovers:?}");
}

/// Cleanup removes only what it can: an entry it cannot delete keeps the
/// staging directory on disk. The failure the caller is told about is still the
/// one the write met, and it names the staging directory that survived, because
/// that directory refuses every later read and write of the same member.
#[test]
fn test_key_pair_write_failure_reports_an_unremovable_staging_directory() {
    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let source = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = source.load_active_kid(&member).unwrap().unwrap();
    let private_key = source.load_private_key(&member, &kid).unwrap();
    let public_key = source.load_public_key(&member, &kid).unwrap();

    let target = local_state_temp_dir();
    let keystore_root = target.path().join("keys");
    let writer = KeystoreAccess::create(&keystore_root).unwrap();
    let member_dir = keystore_root.join(member.as_str());

    let staging_dir = member_dir.clone();
    let staging_kid = kid.clone();
    set_key_pair_staged_hook(move || {
        // Only an empty child directory can be removed, so this entry
        // outlives cleanup and keeps the staging directory alive with it.
        let staging = find_staging_directory(&staging_dir);
        fs::create_dir_all(staging.join("occupied").join("inner")).unwrap();
        // Occupy the publish target so the no-replace rename fails.
        fs::create_dir(staging_dir.join(staging_kid.as_str())).unwrap();
    });
    let error = writer
        .save_key_pair_atomic(&member, &kid, &private_key, &public_key)
        .expect_err("publishing onto an existing key directory must fail");

    let message = error.format_user_message();
    assert!(
        message.contains("refusing to replace existing entry"),
        "{message}"
    );
    assert!(
        message.contains("A key staging directory was left behind at"),
        "{message}"
    );
    let surviving_staging = find_staging_directory(&member_dir);
    assert!(surviving_staging.join("occupied").is_dir());
}

/// Key removal deletes the key documents and the directory holding them. An
/// entry it cannot delete must stop it before anything is gone, or the member
/// keeps an `active` marker pointing at a key whose private half no longer
/// exists.
#[test]
fn test_remove_key_rejects_an_undeletable_key_entry_without_removing_documents() {
    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let access = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = access.load_active_kid(&member).unwrap().unwrap();
    let key_dir = access.root().join(member.as_str()).join(kid.as_str());
    // Sorts after both key documents, so a one-pass delete would reach it last.
    let occupied = key_dir.join("tmp");
    fs::create_dir(&occupied).unwrap();
    fs::write(occupied.join("leftover"), "partial").unwrap();

    let error = access
        .remove_key_with_validation(&member, &kid, |_| Ok(()))
        .expect_err("an undeletable entry must stop key removal");

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert!(key_dir.join("private.json").exists());
    assert!(key_dir.join("public.json").exists());
    assert_eq!(access.load_active_kid(&member).unwrap(), Some(kid));
}

#[test]
fn test_remove_key_removes_an_empty_directory_entry_and_clears_the_active_marker() {
    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let access = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = access.load_active_kid(&member).unwrap().unwrap();
    let key_dir = access.root().join(member.as_str()).join(kid.as_str());
    fs::create_dir(key_dir.join(".tmp-stale")).unwrap();

    let was_active = access
        .remove_key_with_validation(&member, &kid, |_| Ok(()))
        .unwrap();

    assert!(was_active);
    assert!(!key_dir.exists());
    assert_eq!(access.load_active_kid(&member).unwrap(), None);
}

fn find_staging_directory(member_dir: &std::path::Path) -> std::path::PathBuf {
    fs::read_dir(member_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".tmp-"))
        })
        .expect("a key pair write stages into a temporary directory")
}

/// A key directory holding an entry named like an unpublished staging write is
/// the trace of an interrupted write, so its documents are not handed out.
#[test]
fn test_keystore_access_rejects_leftover_staging_entry_in_key_directory() {
    let fixture = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let access = KeystoreAccess::open(fixture.path().join("keys")).unwrap();
    let member = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let kid = access.load_active_kid(&member).unwrap().unwrap();
    let key_dir = access.root().join(member.as_str()).join(kid.as_str());
    fs::write(
        key_dir.join(".public.json.tmp.3f2504e0-4f89-41d3-9a0c-0305e82c3301"),
        "staged",
    )
    .unwrap();

    let error = access.load_public_key(&member, &kid).unwrap_err();

    assert_local_state_path_unsafe(&error);
}
