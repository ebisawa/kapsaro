// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Signing context tests for the loaded local key.
//! Covers the binding between the signing key, the key id and the embedded
//! signer public key.

use std::fs;
use std::path::Path;

use crate::feature::context::crypto::build_signing_context;
use crate::test_support::storage::keystore::active::set_active_kid;
use crate::test_support::storage::keystore::storage::{
    list_kids, load_public_key, save_key_pair_atomic,
};
use crate::test_utils::keygen_helpers::{build_test_private_key, keygen_test};
use crate::test_utils::{setup_member_key_context, setup_test_keystore_from_fixtures};

const ALICE_MEMBER_HANDLE: &str = "alice@example.com";

/// Add a second key to the fixture keystore and make it the active one, so the
/// key the fixture installed is present but no longer the member's default.
fn install_second_active_key(temp_dir: &Path, keystore_root: &Path) -> String {
    let ssh_priv = temp_dir.join(".ssh").join("test_ed25519");
    let ssh_pub = temp_dir.join(".ssh").join("test_ed25519.pub");
    let ssh_pub = fs::read_to_string(ssh_pub).unwrap().trim().to_string();
    let (plaintext, public_key) = keygen_test(ALICE_MEMBER_HANDLE, &ssh_priv, &ssh_pub).unwrap();
    let private_key = build_test_private_key(
        &plaintext,
        &public_key.protected.subject_handle,
        &public_key.protected.kid,
        &ssh_priv,
        &ssh_pub,
    )
    .unwrap();
    save_key_pair_atomic(
        keystore_root,
        ALICE_MEMBER_HANDLE,
        &public_key.protected.kid,
        &private_key,
        &public_key,
    )
    .unwrap();
    set_active_kid(
        ALICE_MEMBER_HANDLE,
        &public_key.protected.kid,
        keystore_root,
    )
    .unwrap();
    public_key.protected.kid
}

/// The embedded signer public key is the public half of the key that signs, so
/// selecting a key other than the active one must move both together.
#[test]
fn test_signing_context_embeds_the_public_key_of_the_selected_kid() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");
    let active_kid = install_second_active_key(temp_dir.path(), &keystore_root);
    let selected_kid = list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
        .unwrap()
        .into_iter()
        .find(|kid| *kid != active_kid)
        .unwrap();

    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&selected_kid));
    let signing = build_signing_context(&key_ctx).unwrap();

    assert_eq!(signing.signer_kid(), selected_kid);
    assert_eq!(signing.signer_pub.protected.kid, selected_kid);
}

/// The embedded signer public key is what readers verify the signature
/// against, so a stored key statement that does not survive that verification
/// refuses the write rather than producing an artifact nobody can open.
#[test]
fn test_signing_context_rejects_signer_public_key_of_another_key() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
    let keystore_root = temp_dir.path().join("keys");
    let active_kid = install_second_active_key(temp_dir.path(), &keystore_root);
    let selected_kid = list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
        .unwrap()
        .into_iter()
        .find(|kid| *kid != active_kid)
        .unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_HANDLE, Some(&selected_kid));

    // The stored document keeps the member and key id its directory names, so
    // the keystore hands it back; only the key material is the other key's,
    // which is what verification has to catch.
    let mut other_public_key =
        load_public_key(&keystore_root, ALICE_MEMBER_HANDLE, &active_kid).unwrap();
    other_public_key.protected.kid = selected_kid.clone();
    other_public_key.protected.subject_handle = ALICE_MEMBER_HANDLE.to_string();
    fs::write(
        keystore_root
            .join(ALICE_MEMBER_HANDLE)
            .join(&selected_kid)
            .join("public.json"),
        serde_json::to_string_pretty(&other_public_key).unwrap(),
    )
    .unwrap();

    let Err(error) = build_signing_context(&key_ctx) else {
        panic!("a signer public key naming another key must be refused");
    };

    let message = error.to_string();
    assert!(
        message.contains("V-KID-DERIVED") || message.contains("derived kid"),
        "unexpected error: {message}"
    );
}
