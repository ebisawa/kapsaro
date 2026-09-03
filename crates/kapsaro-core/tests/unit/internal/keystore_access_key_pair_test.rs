// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key pair persistence tests for the anchored keystore capability.
//! Covers atomic save, reload, key enumeration and key directory identity.

use crate::app_test_utils::{
    build_test_private_key_document, build_test_public_key_document, OTHER_TEST_KEY_SIGNATURE,
    TEST_KEY_SIGNATURE,
};
use crate::io::keystore::access::{
    set_key_directory_open_hook, set_private_key_checked_hook, KeystoreAccess,
    PublicKeySnapshotEntry,
};
use crate::model::identity::{Kid, MemberHandle};
use crate::model::private_key::PrivateKey;
use crate::test_support::storage::keystore::storage::{
    list_kids, load_private_key, load_public_key, save_key_pair_atomic,
};
use crate::test_utils::save_public_key;
use crate::test_utils::TEST_MEMBER_HANDLE;
use crate::test_utils::{
    create_local_state_dir, local_state_temp_dir, write_local_state_file, BOB_MEMBER_HANDLE,
};

const TEST_KID: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
const TEST_KID_2: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE";
/// Ciphertext of a private key document that was never the stored one, so a
/// read that picked it up instead of the stored key is visible in the result.
const SUBSTITUTE_CIPHERTEXT: &str = "c3Vic3RpdHV0ZQ";

#[test]
fn test_save_and_load_private_key() {
    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path();

    let member_handle = TEST_MEMBER_HANDLE;
    let kid = TEST_KID;

    let private_key = build_test_private_key_document(member_handle, kid);
    let public_key = build_test_public_key_document(member_handle, kid, TEST_KEY_SIGNATURE);

    // Save
    save_key_pair_atomic(keystore_root, member_handle, kid, &private_key, &public_key).unwrap();

    // Verify file exists
    let key_path = keystore_root
        .join(member_handle)
        .join(kid)
        .join("private.json");
    assert!(key_path.exists());

    // Load
    let loaded = load_private_key(keystore_root, member_handle, kid).unwrap();

    assert_eq!(
        loaded.protected.subject_handle,
        private_key.protected.subject_handle
    );
    assert_eq!(loaded.protected.kid, private_key.protected.kid);
    assert_eq!(loaded.protected.alg, private_key.protected.alg);
}

#[test]
fn test_save_and_load_public_key() {
    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path();

    let member_handle = TEST_MEMBER_HANDLE;
    let kid = TEST_KID;

    let public_key = build_test_public_key_document(member_handle, kid, TEST_KEY_SIGNATURE);

    // Save
    save_public_key(keystore_root, member_handle, kid, &public_key).unwrap();

    // Verify file exists
    let key_path = keystore_root
        .join(member_handle)
        .join(kid)
        .join("public.json");
    assert!(key_path.exists());

    // Load
    let loaded = load_public_key(keystore_root, member_handle, kid).unwrap();

    assert_eq!(
        loaded.protected.subject_handle,
        public_key.protected.subject_handle
    );
    assert_eq!(loaded.protected.kid, public_key.protected.kid);
    assert_eq!(loaded.signature, public_key.signature);
}

/// A private half stored without its public half names a key that no
/// verification can complete, so the load reports the condition rather than
/// handing back a key that looks whole.
#[test]
fn test_load_private_key_names_a_key_stored_with_one_half_missing() {
    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path();

    let private_key = build_test_private_key_document(TEST_MEMBER_HANDLE, TEST_KID);
    let public_key =
        build_test_public_key_document(TEST_MEMBER_HANDLE, TEST_KID, TEST_KEY_SIGNATURE);
    save_key_pair_atomic(
        keystore_root,
        TEST_MEMBER_HANDLE,
        TEST_KID,
        &private_key,
        &public_key,
    )
    .unwrap();
    std::fs::remove_file(
        keystore_root
            .join(TEST_MEMBER_HANDLE)
            .join(TEST_KID)
            .join("public.json"),
    )
    .unwrap();

    let access = KeystoreAccess::open(keystore_root).unwrap();
    let error = access
        .load_private_key(
            &MemberHandle::try_from(TEST_MEMBER_HANDLE).unwrap(),
            &Kid::try_from(TEST_KID).unwrap(),
        )
        .expect_err("a key missing its public half must not load");

    let message = error.format_user_message();
    assert!(
        message.contains("missing one of the two key documents"),
        "expected the message to name the condition, got: {message}"
    );
    assert!(
        message.contains(TEST_KID),
        "expected the message to name the key, got: {message}"
    );
    assert!(
        message.contains(&format!(
            "kapsaro key remove {TEST_KID} --member-handle {TEST_MEMBER_HANDLE}"
        )),
        "expected a member-bound recovery command, got: {message}"
    );
}

/// Both halves must come from the key directory that was opened first, even
/// when another key directory takes its name while the documents are read.
#[cfg(unix)]
#[test]
fn test_load_key_pair_reads_both_halves_from_one_key_directory() {
    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path();
    let member_handle = TEST_MEMBER_HANDLE;

    for (kid, signature) in [
        (TEST_KID, TEST_KEY_SIGNATURE),
        (TEST_KID_2, OTHER_TEST_KEY_SIGNATURE),
    ] {
        save_key_pair_atomic(
            keystore_root,
            member_handle,
            kid,
            &build_test_private_key_document(member_handle, kid),
            &build_test_public_key_document(member_handle, kid, signature),
        )
        .unwrap();
    }

    let member_path = keystore_root.join(member_handle);
    let hook_ran = std::rc::Rc::new(std::cell::Cell::new(false));
    let hook_ran_inner = hook_ran.clone();
    set_key_directory_open_hook(move || {
        hook_ran_inner.set(true);
        std::fs::rename(member_path.join(TEST_KID), member_path.join("original")).unwrap();
        std::fs::rename(member_path.join(TEST_KID_2), member_path.join(TEST_KID)).unwrap();
    });

    let access = KeystoreAccess::open(keystore_root).unwrap();
    let (private_key, public_key) = access
        .load_key_pair(
            &MemberHandle::try_from(member_handle).unwrap(),
            &Kid::try_from(TEST_KID).unwrap(),
        )
        .unwrap();

    assert_eq!(private_key.protected.kid, TEST_KID);
    assert_eq!(public_key.protected.kid, TEST_KID);
    assert_eq!(public_key.signature, TEST_KEY_SIGNATURE);
    assert!(
        hook_ran.get(),
        "the key-directory-open hook must run so the directory swap it performs is actually exercised"
    );
}

/// Put a world-readable private key document in place of the stored one, the
/// way an account that can write the key directory would.
#[cfg(unix)]
fn substitute_world_readable_private_key(key_dir: &std::path::Path, document: &PrivateKey) {
    use std::os::unix::fs::PermissionsExt;

    let staged = key_dir.join("substitute.json");
    std::fs::write(&staged, serde_json::to_string_pretty(document).unwrap()).unwrap();
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::rename(&staged, key_dir.join("private.json")).unwrap();
}

/// The exposure check and the read have to land on one descriptor. A key
/// directory another account can write is exactly the state the check exists
/// for, and there that account can put a world-readable key in place between a
/// check of the name and a second open of it.
#[cfg(unix)]
#[test]
fn test_load_private_key_reads_the_file_whose_exposure_was_checked() {
    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path();
    let private_key = build_test_private_key_document(TEST_MEMBER_HANDLE, TEST_KID);
    save_key_pair_atomic(
        keystore_root,
        TEST_MEMBER_HANDLE,
        TEST_KID,
        &private_key,
        &build_test_public_key_document(TEST_MEMBER_HANDLE, TEST_KID, TEST_KEY_SIGNATURE),
    )
    .unwrap();

    let key_dir = keystore_root.join(TEST_MEMBER_HANDLE).join(TEST_KID);
    let mut substitute = build_test_private_key_document(TEST_MEMBER_HANDLE, TEST_KID);
    substitute.encrypted.ct = SUBSTITUTE_CIPHERTEXT.to_string();
    let hook_ran = std::rc::Rc::new(std::cell::Cell::new(false));
    let hook_ran_inner = hook_ran.clone();
    set_private_key_checked_hook(move || {
        hook_ran_inner.set(true);
        substitute_world_readable_private_key(&key_dir, &substitute);
    });

    let loaded = KeystoreAccess::open(keystore_root)
        .unwrap()
        .load_private_key(
            &MemberHandle::try_from(TEST_MEMBER_HANDLE).unwrap(),
            &Kid::try_from(TEST_KID).unwrap(),
        )
        .unwrap();

    assert_eq!(loaded.encrypted.ct, private_key.encrypted.ct);
    assert!(
        hook_ran.get(),
        "the private key check hook must run so the substitution it performs is actually exercised"
    );
}

#[test]
fn test_list_kids() {
    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path();

    let member_handle = TEST_MEMBER_HANDLE;
    let kid1 = TEST_KID;
    let kid2 = TEST_KID_2;

    // Create key directories
    let member_path = keystore_root.join(member_handle);
    create_local_state_dir(&member_path.join(kid1));
    create_local_state_dir(&member_path.join(kid2));

    // List kids
    let kids = list_kids(keystore_root, member_handle).unwrap();

    assert_eq!(kids.len(), 2);
    assert!(kids.contains(&kid2.to_string()));
    assert!(kids.contains(&kid1.to_string()));
}

/// Move one member's whole key directory under another member, the way a
/// restore from the wrong backup or a hand-edited keystore would.
fn transplant_key_directory(keystore_root: &std::path::Path, from: &str, to: &str, kid: &str) {
    std::fs::rename(
        keystore_root.join(from).join(kid),
        keystore_root.join(to).join(kid),
    )
    .unwrap();
}

/// A key pair is addressed by the directory holding it, so a document standing
/// there has to state the member and key that directory names.
#[test]
fn test_load_key_pair_refuses_a_pair_stating_another_member() {
    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path();
    save_key_pair_atomic(
        keystore_root,
        TEST_MEMBER_HANDLE,
        TEST_KID,
        &build_test_private_key_document(TEST_MEMBER_HANDLE, TEST_KID),
        &build_test_public_key_document(TEST_MEMBER_HANDLE, TEST_KID, TEST_KEY_SIGNATURE),
    )
    .unwrap();
    save_key_pair_atomic(
        keystore_root,
        BOB_MEMBER_HANDLE,
        TEST_KID_2,
        &build_test_private_key_document(BOB_MEMBER_HANDLE, TEST_KID_2),
        &build_test_public_key_document(BOB_MEMBER_HANDLE, TEST_KID_2, OTHER_TEST_KEY_SIGNATURE),
    )
    .unwrap();
    transplant_key_directory(
        keystore_root,
        BOB_MEMBER_HANDLE,
        TEST_MEMBER_HANDLE,
        TEST_KID_2,
    );

    let access = KeystoreAccess::open(keystore_root).unwrap();
    let error = access
        .load_key_pair(
            &MemberHandle::try_from(TEST_MEMBER_HANDLE).unwrap(),
            &Kid::try_from(TEST_KID_2).unwrap(),
        )
        .unwrap_err();

    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
    assert!(error.to_string().contains(BOB_MEMBER_HANDLE), "{error}");
}

/// The public half is answered on its own by several readers, so it carries
/// the same requirement as the pair.
#[test]
fn test_load_public_key_refuses_a_document_stating_another_key() {
    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path();
    let public_key =
        build_test_public_key_document(TEST_MEMBER_HANDLE, TEST_KID, TEST_KEY_SIGNATURE);
    save_public_key(keystore_root, TEST_MEMBER_HANDLE, TEST_KID_2, &public_key).unwrap();

    let access = KeystoreAccess::open(keystore_root).unwrap();
    let error = access
        .load_public_key(
            &MemberHandle::try_from(TEST_MEMBER_HANDLE).unwrap(),
            &Kid::try_from(TEST_KID_2).unwrap(),
        )
        .unwrap_err();

    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
    assert!(error.to_string().contains(TEST_KID), "{error}");
}

/// The write refuses the same mismatch the read refuses, so a pair that could
/// never be read back does not reach the keystore.
#[test]
fn test_save_key_pair_refuses_a_pair_stating_another_member() {
    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path();

    let error = save_key_pair_atomic(
        keystore_root,
        TEST_MEMBER_HANDLE,
        TEST_KID,
        &build_test_private_key_document(BOB_MEMBER_HANDLE, TEST_KID),
        &build_test_public_key_document(BOB_MEMBER_HANDLE, TEST_KID, TEST_KEY_SIGNATURE),
    )
    .unwrap_err();

    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
    assert!(!keystore_root
        .join(TEST_MEMBER_HANDLE)
        .join(TEST_KID)
        .exists());
}

/// A member namespace that turns unsafe in the moment after a removal is
/// reported against the entry the removal took, not against the directory that
/// held it. Naming the member directory would tell the operator that `keys/bob`
/// was removed while it is still standing, and leave the key that actually went
/// unnamed.
#[test]
fn test_remove_key_names_the_removed_key_when_the_namespace_turns_unsafe() {
    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path();
    let member = MemberHandle::try_from(TEST_MEMBER_HANDLE).unwrap();
    let kid = Kid::try_from(TEST_KID).unwrap();
    save_key_pair_atomic(
        keystore_root,
        TEST_MEMBER_HANDLE,
        TEST_KID,
        &build_test_private_key_document(TEST_MEMBER_HANDLE, TEST_KID),
        &build_test_public_key_document(TEST_MEMBER_HANDLE, TEST_KID, TEST_KEY_SIGNATURE),
    )
    .unwrap();
    let access = KeystoreAccess::open(keystore_root).unwrap();
    let shadowing_entry = keystore_root.join(TEST_MEMBER_HANDLE).join(TEST_KID_2);

    let error = access
        .remove_key_with_validation(&member, &kid, |_| {
            // A regular file under a name the keystore only ever stores a key
            // directory at. Planting it from the validation hook puts it there
            // while the member directory is locked, so the namespace is safe
            // when the removal starts and unsafe when it finishes.
            write_local_state_file(&shadowing_entry, "not a key directory");
            Ok(())
        })
        .unwrap_err();

    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
    let message = error.format_user_message();
    assert!(message.contains(TEST_KID), "{message}");
    assert!(message.contains("was removed"), "{message}");
}

/// `key list` reads this, and it is the command an operator runs to repair an
/// incomplete key, so the snapshot keeps both its identity and every complete
/// sibling even when the active key has lost its public half.
#[test]
fn test_public_key_entries_with_active_keeps_a_key_without_its_public_half() {
    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path();
    let member = MemberHandle::try_from(TEST_MEMBER_HANDLE).unwrap();
    for (kid, signature) in [
        (TEST_KID, TEST_KEY_SIGNATURE),
        (TEST_KID_2, OTHER_TEST_KEY_SIGNATURE),
    ] {
        save_key_pair_atomic(
            keystore_root,
            TEST_MEMBER_HANDLE,
            kid,
            &build_test_private_key_document(TEST_MEMBER_HANDLE, kid),
            &build_test_public_key_document(TEST_MEMBER_HANDLE, kid, signature),
        )
        .unwrap();
    }
    let access = KeystoreAccess::open(keystore_root).unwrap();
    access
        .activate_existing_key(&member, &Kid::try_from(TEST_KID).unwrap())
        .unwrap();
    std::fs::remove_file(
        keystore_root
            .join(TEST_MEMBER_HANDLE)
            .join(TEST_KID)
            .join("public.json"),
    )
    .unwrap();

    let (active, entries) = access.load_public_key_entries_with_active(&member).unwrap();

    assert_eq!(active.as_ref().map(Kid::as_str), Some(TEST_KID));
    assert_eq!(
        entries
            .iter()
            .map(PublicKeySnapshotEntry::kid)
            .map(Kid::as_str)
            .collect::<Vec<_>>(),
        vec![TEST_KID, TEST_KID_2]
    );
    assert!(matches!(
        &entries[0],
        PublicKeySnapshotEntry::MissingPublicDocument { kid } if kid.as_str() == TEST_KID
    ));
    assert!(matches!(
        &entries[1],
        PublicKeySnapshotEntry::Complete { kid, public_key }
            if kid.as_str() == TEST_KID_2
                && public_key.protected.kid == TEST_KID_2
    ));
}
