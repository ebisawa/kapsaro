// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for core/usecase/key/helpers module
//!
//! Tests for key operation helper functions.

use crate::test_utils::ALICE_MEMBER_ID;
use crate::test_utils::{create_test_private_key, keygen_test, setup_test_keystore_from_fixtures};
use secretenv::io::keystore::active::set_active_kid;
use secretenv::io::keystore::helpers::resolve_kid;
use secretenv::io::keystore::resolver::KeystoreResolver;
use secretenv::io::keystore::storage::{load_private_key, load_public_key, save_key_pair_atomic};
use tempfile::TempDir;

#[test]
fn test_ensure_keystore_dir() {
    let temp_dir = TempDir::new().unwrap();
    let home = Some(temp_dir.path().to_path_buf());

    let keystore_root = KeystoreResolver::resolve_and_ensure(home.as_ref()).unwrap();

    assert!(keystore_root.exists());
    assert!(keystore_root.is_dir());
}

#[test]
fn test_save_and_activate() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");
    let ssh_pub_content = std::fs::read_to_string(temp_dir.path().join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let ssh_priv = temp_dir.path().join(".ssh/test_ed25519");
    let (private_key_plaintext, public_key) =
        keygen_test(ALICE_MEMBER_ID, &ssh_priv, &ssh_pub_content).unwrap();
    let kid = &public_key.protected.kid;
    let private_key = create_test_private_key(
        &private_key_plaintext,
        ALICE_MEMBER_ID,
        kid,
        &ssh_priv,
        &ssh_pub_content,
    )
    .unwrap();

    // Save keys
    save_key_pair_atomic(
        &keystore_root,
        ALICE_MEMBER_ID,
        kid,
        &private_key,
        &public_key,
    )
    .unwrap();

    // Activate
    set_active_kid(ALICE_MEMBER_ID, kid, &keystore_root).unwrap();

    // Verify keys are saved
    let loaded_private = load_private_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();
    let loaded_public = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();

    assert_eq!(loaded_private.protected.kid, *kid);
    assert_eq!(loaded_public.protected.kid, *kid);

    // Verify active kid is set
    let active_kid = resolve_kid(&keystore_root, ALICE_MEMBER_ID, None).unwrap();
    assert_eq!(active_kid, *kid);
}

#[test]
fn test_save_without_activate() {
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");
    let ssh_pub_content = std::fs::read_to_string(temp_dir.path().join(".ssh/test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let ssh_priv = temp_dir.path().join(".ssh/test_ed25519");
    let (private_key_plaintext, public_key) =
        keygen_test(ALICE_MEMBER_ID, &ssh_priv, &ssh_pub_content).unwrap();
    let kid = &public_key.protected.kid;
    let private_key = create_test_private_key(
        &private_key_plaintext,
        ALICE_MEMBER_ID,
        kid,
        &ssh_priv,
        &ssh_pub_content,
    )
    .unwrap();

    // Save without activating
    save_key_pair_atomic(
        &keystore_root,
        ALICE_MEMBER_ID,
        kid,
        &private_key,
        &public_key,
    )
    .unwrap();

    // Verify keys are saved
    let loaded_private = load_private_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();
    let loaded_public = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();

    assert_eq!(loaded_private.protected.kid, *kid);
    assert_eq!(loaded_public.protected.kid, *kid);
}
