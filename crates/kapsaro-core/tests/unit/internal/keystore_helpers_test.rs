// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for keystore helper resolution of kids and owning members.
//! Covers resolution order, query error phrasing and member lookup by kid.

use crate::app_test_utils::build_test_private_key_document;
use crate::io::config::paths::get_base_dir;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::keystore::helpers::{find_member_by_kid, resolve_member_kid_query};
use crate::io::keystore::paths::get_keystore_root_from_base;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::{
    Attestation, IdentityKeys, JwkOkpPublicKey, PublicKey, PublicKeyProtected,
};
use crate::test_support::storage::keystore::storage::save_key_pair_atomic;
use crate::test_utils::save_public_key;
use crate::test_utils::{local_state_temp_dir, EnvGuard};

const B64URL_32: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const B64URL_64: &str =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn dummy_public_key(member_handle: &str, kid: &str, created_at: &str) -> PublicKey {
    PublicKey {
        protected: PublicKeyProtected {
            format: crate::model::wire::format::PUBLIC_KEY_V1.to_string(),
            subject_handle: member_handle.to_string(),
            kid: kid.to_string(),
            keys: IdentityKeys {
                kem: JwkOkpPublicKey {
                    kty: "OKP".to_string(),
                    crv: crate::model::wire::jwk::CURVE_X25519.to_string(),
                    x: B64URL_32.to_string(),
                },
                sig: JwkOkpPublicKey {
                    kty: "OKP".to_string(),
                    crv: crate::model::wire::jwk::CURVE_ED25519.to_string(),
                    x: B64URL_32.to_string(),
                },
            },
            attestation: Attestation {
                method: "ssh-sign".to_string(),
                pub_: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTest test@test".to_string(),
                sig: B64URL_64.to_string(),
            },
            binding_claims: None,
            expires_at: "2027-03-01T00:00:00Z".to_string(),
            created_at: Some(created_at.to_string()),
        },
        signature: B64URL_64.to_string(),
    }
}

#[test]
fn test_resolve_kid_with_override() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME"]);

    let temp_dir = local_state_temp_dir();
    std::env::set_var("KAPSARO_HOME", temp_dir.path().to_str().unwrap());

    // Use unique member_handle to avoid interference from other parallel tests
    let member_handle = format!("alice-override-{}@example.com", uuid::Uuid::new_v4());

    let pub1 = dummy_public_key(
        &member_handle,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        "2026-03-01T00:00:00Z",
    );
    let pub2 = dummy_public_key(
        &member_handle,
        "9N4R1H8VW6PKT3XNC5JY2F9AR8GD7M2Q",
        "2026-03-02T00:00:00Z",
    );

    let base_dir = get_base_dir().unwrap();
    let keystore_root = get_keystore_root_from_base(&base_dir);
    save_public_key(&keystore_root, &member_handle, &pub1.protected.kid, &pub1).unwrap();
    save_public_key(&keystore_root, &member_handle, &pub2.protected.kid, &pub2).unwrap();
    let access = KeystoreAccess::open(&keystore_root).unwrap();
    let member_handle = MemberHandle::try_from(member_handle).unwrap();

    // Override should work
    let resolved = access
        .resolve_kid(
            &member_handle,
            Some("7m2q-9d4r-1h8v-w6pk-t3xn-c5jy-2f9a-r8gd"),
        )
        .unwrap();
    assert_eq!(resolved, pub1.protected.kid);

    // Invalid override should fail
    let result = access.resolve_kid(&member_handle, Some("invalid_kid"));
    assert!(result.is_err());
}

#[test]
fn test_resolve_kid_with_active() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME"]);

    let temp_dir = local_state_temp_dir();
    std::env::set_var("KAPSARO_HOME", temp_dir.path().to_str().unwrap());

    // Use unique member_handle to avoid interference from other parallel tests
    let member_handle = format!("alice-active-{}@example.com", uuid::Uuid::new_v4());

    let pub1 = dummy_public_key(
        &member_handle,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        "2026-03-01T00:00:00Z",
    );
    let pub2 = dummy_public_key(
        &member_handle,
        "9N4R1H8VW6PKT3XNC5JY2F9AR8GD7M2Q",
        "2026-03-02T00:00:00Z",
    );

    let base_dir = get_base_dir().unwrap();
    let keystore_root = get_keystore_root_from_base(&base_dir);
    save_public_key(&keystore_root, &member_handle, &pub1.protected.kid, &pub1).unwrap();
    save_public_key(&keystore_root, &member_handle, &pub2.protected.kid, &pub2).unwrap();
    let access = KeystoreAccess::open(&keystore_root).unwrap();
    let member_handle = MemberHandle::try_from(member_handle).unwrap();
    let active_kid = Kid::try_from(pub1.protected.kid.as_str()).unwrap();

    // Set active kid
    access
        .set_active_kid_unchecked(&member_handle, &active_kid)
        .unwrap();

    // Should use active kid
    let resolved = access.resolve_kid(&member_handle, None).unwrap();
    assert_eq!(resolved, pub1.protected.kid);
}

#[test]
fn test_resolve_kid_fallback_to_latest() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME"]);

    let temp_dir = local_state_temp_dir();
    std::env::set_var("KAPSARO_HOME", temp_dir.path().to_str().unwrap());

    // Use unique member_handle to avoid interference from other parallel tests
    let member_handle = format!("alice-fallback-{}@example.com", uuid::Uuid::new_v4());

    let pub1 = dummy_public_key(
        &member_handle,
        "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
        "2026-03-01T00:00:00Z",
    );
    let pub2 = dummy_public_key(
        &member_handle,
        "00000000000000000000000000000001",
        "2026-03-02T00:00:00Z",
    );

    let base_dir = get_base_dir().unwrap();
    let keystore_root = get_keystore_root_from_base(&base_dir);
    // Both halves are stored, because a key resolved without being named is a
    // key the caller goes on to sign or decrypt with.
    save_key_pair(&keystore_root, &member_handle, &pub1);
    save_key_pair(&keystore_root, &member_handle, &pub2);
    let access = KeystoreAccess::open(&keystore_root).unwrap();
    let member_handle = MemberHandle::try_from(member_handle).unwrap();

    // No active kid set, should use the newest key by created_at.
    let resolved = access.resolve_kid(&member_handle, None).unwrap();
    assert_eq!(resolved, pub2.protected.kid);
}

/// Store a whole key pair under the member and key the public half states.
fn save_key_pair(keystore_root: &std::path::Path, member_handle: &str, public_key: &PublicKey) {
    let kid = public_key.protected.kid.as_str();
    save_key_pair_atomic(
        keystore_root,
        member_handle,
        kid,
        &build_test_private_key_document(member_handle, kid),
        public_key,
    )
    .unwrap();
}

#[test]
fn test_resolve_kid_no_keys() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME"]);

    let temp_dir = local_state_temp_dir();
    std::env::set_var("KAPSARO_HOME", temp_dir.path().to_str().unwrap());

    let base_dir = get_base_dir().unwrap();
    let keystore_root = get_keystore_root_from_base(&base_dir);

    // Use unique member_handle to avoid interference from other parallel tests
    let member_handle = format!("nonexistent-{}@example.com", uuid::Uuid::new_v4());
    let access = KeystoreAccess::create(&keystore_root).unwrap();
    let member_handle = MemberHandle::try_from(member_handle).unwrap();

    // Should fail with no keys
    let result = access.resolve_kid(&member_handle, None);
    assert!(result.is_err());
}

#[test]
fn test_resolve_member_kid_query_names_the_member_when_the_kid_is_absent() {
    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path();
    let member_handle = format!("alice-absent-{}@example.com", uuid::Uuid::new_v4());
    let public_key = dummy_public_key(
        &member_handle,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        "2026-03-01T00:00:00Z",
    );
    save_public_key(
        keystore_root,
        &member_handle,
        &public_key.protected.kid,
        &public_key,
    )
    .unwrap();
    let access = KeystoreAccess::open(keystore_root).unwrap();
    let member = MemberHandle::try_from(member_handle.clone()).unwrap();

    let error = resolve_member_kid_query(&access, &member, "9N4R1H8VW6PKT3XNC5JY2F9AR8GD7M2Q")
        .expect_err("an absent kid must be reported against the queried member");

    assert_eq!(error.kind(), crate::ErrorKind::NotFound);
    let message = error.format_user_message();
    assert!(message.contains(&member_handle), "unexpected: {message}");
    assert!(message.contains("9N4R"), "unexpected: {message}");
}

#[test]
fn test_find_member_by_kid_returns_the_owning_member() {
    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path();
    let owner = format!("alice-owner-{}@example.com", uuid::Uuid::new_v4());
    let other = format!("bob-other-{}@example.com", uuid::Uuid::new_v4());
    let owned = dummy_public_key(
        &owner,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        "2026-03-01T00:00:00Z",
    );
    let unrelated = dummy_public_key(
        &other,
        "9N4R1H8VW6PKT3XNC5JY2F9AR8GD7M2Q",
        "2026-03-02T00:00:00Z",
    );
    save_public_key(keystore_root, &owner, &owned.protected.kid, &owned).unwrap();
    save_public_key(keystore_root, &other, &unrelated.protected.kid, &unrelated).unwrap();
    let access = KeystoreAccess::open(keystore_root).unwrap();

    let resolved = find_member_by_kid(&access, "7m2q-9d4r-1h8v-w6pk-t3xn-c5jy-2f9a-r8gd").unwrap();

    assert_eq!(resolved.as_str(), owner);
}

/// The lookup reads directory names alone, so a name that is not a canonical
/// kid must not be offered as one to the resolution that follows.
#[test]
fn test_find_member_by_kid_ignores_a_member_directory_that_is_not_a_kid() {
    let temp_dir = local_state_temp_dir();
    let keystore_root = temp_dir.path();
    let owner = format!("alice-mixed-{}@example.com", uuid::Uuid::new_v4());
    let owned = dummy_public_key(
        &owner,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        "2026-03-01T00:00:00Z",
    );
    save_public_key(keystore_root, &owner, &owned.protected.kid, &owned).unwrap();
    std::fs::create_dir(keystore_root.join(&owner).join("notes")).unwrap();
    let access = KeystoreAccess::open(keystore_root).unwrap();

    let resolved = find_member_by_kid(&access, &owned.protected.kid).unwrap();

    assert_eq!(resolved.as_str(), owner);
}

#[test]
fn test_find_member_by_kid_reports_an_unknown_kid_as_not_found() {
    let temp_dir = local_state_temp_dir();
    let access = KeystoreAccess::create(temp_dir.path()).unwrap();

    let error = find_member_by_kid(&access, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD")
        .expect_err("an empty keystore owns no kid");

    assert_eq!(error.kind(), crate::ErrorKind::NotFound);
}
