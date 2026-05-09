// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for keystore helpers

use crate::test_utils::save_public_key;
use crate::test_utils::EnvGuard;
use secretenv::io::config::paths::get_base_dir;
use secretenv::io::keystore::active::set_active_kid;
use secretenv::io::keystore::helpers::resolve_kid;
use secretenv::io::keystore::paths::get_keystore_root_from_base;
use secretenv::model::public_key::{
    Attestation, Identity, IdentityKeys, JwkOkpPublicKey, PublicKey, PublicKeyProtected,
};
use tempfile::TempDir;

const B64URL_32: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const B64URL_64: &str =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn dummy_public_key(member_handle: &str, kid: &str, created_at: &str) -> PublicKey {
    PublicKey {
        protected: PublicKeyProtected {
            format: secretenv::model::wire::format::PUBLIC_KEY_V5.to_string(),
            subject_handle: member_handle.to_string(),
            kid: kid.to_string(),
            identity: Identity {
                keys: IdentityKeys {
                    kem: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: secretenv::model::wire::jwk::CRV_X25519.to_string(),
                        x: B64URL_32.to_string(),
                    },
                    sig: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: secretenv::model::wire::jwk::CRV_ED25519.to_string(),
                        x: B64URL_32.to_string(),
                    },
                },
                attestation: Attestation {
                    method: "ssh-sign".to_string(),
                    pub_: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTest test@test"
                        .to_string(),
                    sig: B64URL_64.to_string(),
                },
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
    let _guard = EnvGuard::new(&["SECRETENV_HOME"]);

    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("SECRETENV_HOME", temp_dir.path().to_str().unwrap());

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

    // Override should work
    let resolved = resolve_kid(
        &keystore_root,
        &member_handle,
        Some("7m2q-9d4r-1h8v-w6pk-t3xn-c5jy-2f9a-r8gd"),
    )
    .unwrap();
    assert_eq!(resolved, pub1.protected.kid);

    // Invalid override should fail
    let result = resolve_kid(&keystore_root, &member_handle, Some("invalid_kid"));
    assert!(result.is_err());
}

#[test]
fn test_resolve_kid_with_unique_prefix_override() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME"]);

    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("SECRETENV_HOME", temp_dir.path().to_str().unwrap());

    let member_handle = format!("alice-prefix-{}@example.com", uuid::Uuid::new_v4());

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

    let resolved = resolve_kid(&keystore_root, &member_handle, Some("7m2q-9d4r")).unwrap();
    assert_eq!(resolved, pub1.protected.kid);
}

#[test]
fn test_resolve_kid_with_ambiguous_prefix_override_error() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME"]);

    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("SECRETENV_HOME", temp_dir.path().to_str().unwrap());

    let member_handle = format!("alice-ambiguous-{}@example.com", uuid::Uuid::new_v4());

    let pub1 = dummy_public_key(
        &member_handle,
        "83AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "2026-03-01T00:00:00Z",
    );
    let pub2 = dummy_public_key(
        &member_handle,
        "83BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "2026-03-02T00:00:00Z",
    );

    let base_dir = get_base_dir().unwrap();
    let keystore_root = get_keystore_root_from_base(&base_dir);
    save_public_key(&keystore_root, &member_handle, &pub1.protected.kid, &pub1).unwrap();
    save_public_key(&keystore_root, &member_handle, &pub2.protected.kid, &pub2).unwrap();

    let error = resolve_kid(&keystore_root, &member_handle, Some("83")).unwrap_err();
    assert!(
        error.to_string().contains("ambiguous"),
        "error should mention ambiguity: {error}"
    );
}

#[test]
fn test_resolve_kid_with_active() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME"]);

    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("SECRETENV_HOME", temp_dir.path().to_str().unwrap());

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

    // Set active kid
    set_active_kid(&member_handle, &pub1.protected.kid, &keystore_root).unwrap();

    // Should use active kid
    let resolved = resolve_kid(&keystore_root, &member_handle, None).unwrap();
    assert_eq!(resolved, pub1.protected.kid);
}

#[test]
fn test_resolve_kid_fallback_to_latest() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME"]);

    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("SECRETENV_HOME", temp_dir.path().to_str().unwrap());

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
    save_public_key(&keystore_root, &member_handle, &pub1.protected.kid, &pub1).unwrap();
    save_public_key(&keystore_root, &member_handle, &pub2.protected.kid, &pub2).unwrap();

    // No active kid set, should use the newest key by created_at.
    let resolved = resolve_kid(&keystore_root, &member_handle, None).unwrap();
    assert_eq!(resolved, pub2.protected.kid);
}

#[test]
fn test_resolve_kid_no_keys() {
    let _guard = EnvGuard::new(&["SECRETENV_HOME"]);

    let temp_dir = TempDir::new().unwrap();
    std::env::set_var("SECRETENV_HOME", temp_dir.path().to_str().unwrap());

    let base_dir = get_base_dir().unwrap();
    let keystore_root = get_keystore_root_from_base(&base_dir);

    // Use unique member_handle to avoid interference from other parallel tests
    let member_handle = format!("nonexistent-{}@example.com", uuid::Uuid::new_v4());

    // Should fail with no keys
    let result = resolve_kid(&keystore_root, &member_handle, None);
    assert!(result.is_err());
}
