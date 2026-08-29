// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Keystore-backed crypto context loading.
//! Pins which value the loader treats as the identity of the key it loaded.

use super::load_crypto_context_from_keystore;
use crate::io::keystore::access::KeystoreAccess;
use crate::model::identity::MemberHandle;
use crate::test_utils::ed25519_backend::Ed25519DirectBackend;
use crate::test_utils::{
    build_test_private_key, create_local_state_dir, keygen_test, restrict_local_state_file,
    setup_test_keystore_from_fixtures, ALICE_MEMBER_HANDLE,
};
use std::fs;
use std::path::Path;

/// Copy a stored key pair into a second directory named by another kid.
///
/// The documents keep the kid they were signed with, so the directory name and
/// the document disagree and the loader has to pick one of them.
fn copy_key_pair_under_other_kid(member_dir: &Path, source_kid: &str, other_kid: &str) {
    let source = member_dir.join(source_kid);
    let destination = member_dir.join(other_kid);
    create_local_state_dir(&destination);
    for name in ["private.json", "public.json"] {
        fs::copy(source.join(name), destination.join(name)).unwrap();
        restrict_local_state_file(&destination.join(name));
    }
}

fn only_stored_kid(member_dir: &Path) -> String {
    let mut entries = fs::read_dir(member_dir)
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            entry
                .file_type()
                .unwrap()
                .is_dir()
                .then(|| entry.file_name().to_string_lossy().into_owned())
        })
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 1, "{entries:?}");
    entries.pop().unwrap()
}

/// Build a kid that no stored document carries, by generating a second key and
/// keeping only its identifier.
fn build_unused_kid(home: &Path) -> String {
    let ssh_public_key = fs::read_to_string(home.join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let ssh_private_key = home.join(".ssh/test_ed25519");
    let (plaintext, public_key) =
        keygen_test(ALICE_MEMBER_HANDLE, &ssh_private_key, &ssh_public_key).unwrap();
    build_test_private_key(
        &plaintext,
        ALICE_MEMBER_HANDLE,
        &public_key.protected.kid,
        &ssh_private_key,
        &ssh_public_key,
    )
    .unwrap();
    public_key.protected.kid
}

/// The directory a key is stored under and the kid its signature was made over
/// have to agree. Accepting a disagreement would leave the storage name and the
/// key identity as two different answers to which key was loaded.
///
/// The refusal comes from the keystore, which settles the same question for
/// every reader, so the rule it raises is what this pins: asserting only that
/// both kids appear would also pass on a message raised somewhere else.
#[test]
fn test_load_crypto_context_refuses_a_key_stored_under_another_kid() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(ALICE_MEMBER_HANDLE);
    let document_kid = only_stored_kid(&member_dir);
    let directory_kid = build_unused_kid(temp_dir.path());
    copy_key_pair_under_other_kid(&member_dir, &document_kid, &directory_kid);
    let ssh_public_key = fs::read_to_string(temp_dir.path().join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let backend = Ed25519DirectBackend::new(&temp_dir.path().join(".ssh/test_ed25519")).unwrap();

    let result = load_crypto_context_from_keystore(
        KeystoreAccess::open(&keystore_root).unwrap(),
        MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap(),
        Some(directory_kid.as_str()),
        Box::new(backend),
        ssh_public_key,
        None,
    );

    let Err(error) = result else {
        panic!("a key stored under another kid must be refused");
    };
    assert_eq!(error.recovery(), Some("E_LOCAL_STATE_PATH_UNSAFE"));
    let message = error.format_user_message();
    assert!(message.contains(&directory_kid), "{message}");
    assert!(message.contains(&document_kid), "{message}");
    assert!(message.contains("stored as member"), "{message}");
}
