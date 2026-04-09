// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::test_utils::save_public_key;
use crate::test_utils::TEST_MEMBER_ID;
use secretenv::io::keystore::storage::*;
use secretenv::model::private_key::{
    EncryptedData, PrivateKey, PrivateKeyAlgorithm, PrivateKeyProtected,
};
use secretenv::model::public_key::{
    Attestation, Identity, IdentityKeys, JwkOkpPublicKey, PublicKey, PublicKeyProtected,
};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

const TEST_KID: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
const TEST_KID_2: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE";

#[test]
fn test_save_and_load_private_key() {
    let temp_dir = TempDir::new().unwrap();
    #[cfg(unix)]
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let keystore_root = temp_dir.path();

    let member_id = TEST_MEMBER_ID;
    let kid = TEST_KID;

    let private_key = PrivateKey {
        protected: PrivateKeyProtected {
            format: secretenv::model::identifiers::format::PRIVATE_KEY_V4.to_string(),
            member_id: member_id.to_string(),
            kid: kid.to_string(),
            alg: PrivateKeyAlgorithm::SshSig {
                fpr: "sha256:TEST123".to_string(),
                salt: "c2FsdA".to_string(),
                aead: secretenv::model::identifiers::alg::AEAD_XCHACHA20_POLY1305.to_string(),
            },
            created_at: "2024-01-01T00:00:00Z".to_string(),
            expires_at: "2025-01-01T00:00:00Z".to_string(),
        },
        encrypted: EncryptedData {
            nonce: "bm9uY2U".to_string(),
            ct: "Y3Q".to_string(),
        },
    };

    let public_key = PublicKey {
        protected: PublicKeyProtected {
            format: secretenv::model::identifiers::format::PUBLIC_KEY_V4.to_string(),
            member_id: member_id.to_string(),
            kid: kid.to_string(),
            identity: Identity {
                keys: IdentityKeys {
                    kem: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: secretenv::model::identifiers::jwk::CRV_X25519.to_string(),
                        x: "a2VtcHVi".to_string(),
                    },
                    sig: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: secretenv::model::identifiers::jwk::CRV_ED25519.to_string(),
                        x: "c2lncHVi".to_string(),
                    },
                },
                attestation: Attestation {
                    method: secretenv::io::ssh::protocol::constants::ATTESTATION_METHOD_SSH_SIGN
                        .to_string(),
                    pub_: "ssh-ed25519 AAAA...".to_string(),
                    sig: "c2ln".to_string(),
                },
            },
            binding_claims: None,
            expires_at: "2025-01-01T00:00:00Z".to_string(),
            created_at: Some("2024-01-01T00:00:00Z".to_string()),
        },
        signature: "c2VsZnNpZw".to_string(),
    };

    // Save
    save_key_pair_atomic(keystore_root, member_id, kid, &private_key, &public_key).unwrap();

    // Verify file exists
    let key_path = keystore_root.join(member_id).join(kid).join("private.json");
    assert!(key_path.exists());

    // Load
    let loaded = load_private_key(keystore_root, member_id, kid).unwrap();

    assert_eq!(loaded.protected.member_id, private_key.protected.member_id);
    assert_eq!(loaded.protected.kid, private_key.protected.kid);
    assert_eq!(loaded.protected.alg, private_key.protected.alg);
}

#[test]
fn test_save_and_load_public_key() {
    let temp_dir = TempDir::new().unwrap();
    #[cfg(unix)]
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let keystore_root = temp_dir.path();

    let member_id = TEST_MEMBER_ID;
    let kid = TEST_KID;

    let public_key = PublicKey {
        protected: PublicKeyProtected {
            format: secretenv::model::identifiers::format::PUBLIC_KEY_V4.to_string(),
            member_id: member_id.to_string(),
            kid: kid.to_string(),
            identity: Identity {
                keys: IdentityKeys {
                    kem: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: secretenv::model::identifiers::jwk::CRV_X25519.to_string(),
                        x: "a2VtcHVi".to_string(),
                    },
                    sig: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: secretenv::model::identifiers::jwk::CRV_ED25519.to_string(),
                        x: "c2lncHVi".to_string(),
                    },
                },
                attestation: Attestation {
                    method: secretenv::io::ssh::protocol::constants::ATTESTATION_METHOD_SSH_SIGN
                        .to_string(),
                    pub_: "ssh-ed25519 AAAA...".to_string(),
                    sig: "c2ln".to_string(),
                },
            },
            binding_claims: None,
            expires_at: "2025-01-01T00:00:00Z".to_string(),
            created_at: Some("2024-01-01T00:00:00Z".to_string()),
        },
        signature: "c2VsZnNpZw".to_string(),
    };

    // Save
    save_public_key(keystore_root, member_id, kid, &public_key).unwrap();

    // Verify file exists
    let key_path = keystore_root.join(member_id).join(kid).join("public.json");
    assert!(key_path.exists());

    // Load
    let loaded = load_public_key(keystore_root, member_id, kid).unwrap();

    assert_eq!(loaded.protected.member_id, public_key.protected.member_id);
    assert_eq!(loaded.protected.kid, public_key.protected.kid);
    assert_eq!(loaded.signature, public_key.signature);
}

#[test]
fn test_list_kids() {
    let temp_dir = TempDir::new().unwrap();
    let keystore_root = temp_dir.path();

    let member_id = TEST_MEMBER_ID;
    let kid1 = TEST_KID;
    let kid2 = TEST_KID_2;

    // Create key directories
    let member_path = keystore_root.join(member_id);
    fs::create_dir_all(member_path.join(kid1)).unwrap();
    fs::create_dir_all(member_path.join(kid2)).unwrap();

    // List kids
    let kids = list_kids(keystore_root, member_id).unwrap();

    assert_eq!(kids.len(), 2);
    assert!(kids.contains(&kid1.to_string()));
    assert!(kids.contains(&kid2.to_string()));
}
