// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::test_utils::save_public_key;
use crate::test_utils::TEST_MEMBER_HANDLE;
use secretenv_core::cli_api::test_support::domain::private_key::{
    PrivateKey, PrivateKeyAlgorithm, PrivateKeyEncData, PrivateKeyProtected,
};
use secretenv_core::cli_api::test_support::domain::public_key::{
    Attestation, IdentityKeys, JwkOkpPublicKey, PublicKey, PublicKeyProtected,
};
use secretenv_core::cli_api::test_support::storage::keystore::storage::{
    list_kids, load_private_key, load_public_key, save_key_pair_atomic,
};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

const TEST_KID: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
const TEST_KID_2: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE";
const B64URL_24: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const B64URL_32: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const B64URL_64: &str =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn test_save_and_load_private_key() {
    let temp_dir = TempDir::new().unwrap();
    #[cfg(unix)]
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let keystore_root = temp_dir.path();

    let member_handle = TEST_MEMBER_HANDLE;
    let kid = TEST_KID;

    let private_key = PrivateKey {
        protected: PrivateKeyProtected {
            format: secretenv_core::cli_api::test_support::domain::wire::format::PRIVATE_KEY_V7.to_string(),
            subject_handle: member_handle.to_string(),
            kid: kid.to_string(),
            alg: PrivateKeyAlgorithm::SshSig {
                fpr: "SHA256:TEST123".to_string(),
                ikm_salt: B64URL_32.to_string(),
                hkdf_salt: B64URL_32.to_string(),
                aead: secretenv_core::cli_api::test_support::domain::wire::algorithm::AEAD_XCHACHA20_POLY1305
                    .to_string(),
            },
            created_at: "2024-01-01T00:00:00Z".to_string(),
            expires_at: "2025-01-01T00:00:00Z".to_string(),
        },
        encrypted: PrivateKeyEncData {
            nonce: B64URL_24.to_string(),
            ct: "Y3Q".to_string(),
        },
    };

    let public_key = PublicKey {
        protected: PublicKeyProtected {
            format: secretenv_core::cli_api::test_support::domain::wire::format::PUBLIC_KEY_V7.to_string(),
            subject_handle: member_handle.to_string(),
            kid: kid.to_string(),
                            keys: IdentityKeys {
                    kem: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: secretenv_core::cli_api::test_support::domain::wire::jwk::CURVE_X25519.to_string(),
                        x: B64URL_32.to_string(),
                    },
                    sig: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: secretenv_core::cli_api::test_support::domain::wire::jwk::CURVE_ED25519.to_string(),
                        x: B64URL_32.to_string(),
                    },
                },
                attestation: Attestation {
                    method:
                        secretenv_core::cli_api::test_support::storage::ssh::protocol::constants::ATTESTATION_METHOD_SSH_SIGN
                            .to_string(),
                    pub_: "ssh-ed25519 AAAA...".to_string(),
                    sig: B64URL_64.to_string(),
                },
            binding_claims: None,
            expires_at: "2025-01-01T00:00:00Z".to_string(),
            created_at: Some("2024-01-01T00:00:00Z".to_string()),
        },
        signature: B64URL_64.to_string(),
    };

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
    let temp_dir = TempDir::new().unwrap();
    #[cfg(unix)]
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let keystore_root = temp_dir.path();

    let member_handle = TEST_MEMBER_HANDLE;
    let kid = TEST_KID;

    let public_key = PublicKey {
        protected: PublicKeyProtected {
            format: secretenv_core::cli_api::test_support::domain::wire::format::PUBLIC_KEY_V7.to_string(),
            subject_handle: member_handle.to_string(),
            kid: kid.to_string(),
                            keys: IdentityKeys {
                    kem: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: secretenv_core::cli_api::test_support::domain::wire::jwk::CURVE_X25519.to_string(),
                        x: B64URL_32.to_string(),
                    },
                    sig: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: secretenv_core::cli_api::test_support::domain::wire::jwk::CURVE_ED25519.to_string(),
                        x: B64URL_32.to_string(),
                    },
                },
                attestation: Attestation {
                    method:
                        secretenv_core::cli_api::test_support::storage::ssh::protocol::constants::ATTESTATION_METHOD_SSH_SIGN
                            .to_string(),
                    pub_: "ssh-ed25519 AAAA...".to_string(),
                    sig: B64URL_64.to_string(),
                },
            binding_claims: None,
            expires_at: "2025-01-01T00:00:00Z".to_string(),
            created_at: Some("2024-01-01T00:00:00Z".to_string()),
        },
        signature: B64URL_64.to_string(),
    };

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

#[test]
fn test_list_kids() {
    let temp_dir = TempDir::new().unwrap();
    let keystore_root = temp_dir.path();

    let member_handle = TEST_MEMBER_HANDLE;
    let kid1 = TEST_KID;
    let kid2 = TEST_KID_2;

    // Create key directories
    let member_path = keystore_root.join(member_handle);
    fs::create_dir_all(member_path.join(kid1)).unwrap();
    fs::create_dir_all(member_path.join(kid2)).unwrap();

    // List kids
    let kids = list_kids(keystore_root, member_handle).unwrap();

    assert_eq!(kids.len(), 2);
    assert!(kids.contains(&kid1.to_string()));
    assert!(kids.contains(&kid2.to_string()));
}
