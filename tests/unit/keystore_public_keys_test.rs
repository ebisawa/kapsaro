// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for keystore public keys

use crate::test_utils::save_public_key;
use secretenv::io::keystore::active::set_active_kid;
use secretenv::io::keystore::public_keys::load_public_keys_for_member_handles;
use secretenv::model::public_key::{
    Attestation, Identity, IdentityKeys, JwkOkpPublicKey, PublicKey, PublicKeyProtected,
};
use tempfile::TempDir;

const B64URL_32: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const B64URL_64: &str =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn build_test_public_key(member_handle: &str, kid: &str) -> PublicKey {
    PublicKey {
        protected: PublicKeyProtected {
            format: secretenv::model::identifiers::format::PUBLIC_KEY_V5.to_string(),
            subject_handle: member_handle.to_string(),
            kid: kid.to_string(),
            identity: Identity {
                keys: IdentityKeys {
                    kem: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: secretenv::model::identifiers::jwk::CRV_X25519.to_string(),
                        x: B64URL_32.to_string(),
                    },
                    sig: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: secretenv::model::identifiers::jwk::CRV_ED25519.to_string(),
                        x: B64URL_32.to_string(),
                    },
                },
                attestation: Attestation {
                    method: secretenv::io::ssh::protocol::constants::ATTESTATION_METHOD_SSH_SIGN
                        .to_string(),
                    pub_: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE".to_string(),
                    sig: B64URL_64.to_string(),
                },
            },
            binding_claims: None,
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            created_at: Some("2025-01-01T00:00:00Z".to_string()),
        },
        signature: B64URL_64.to_string(),
    }
}

#[test]
fn test_load_public_keys_for_member_handles() {
    let temp_dir = TempDir::new().unwrap();
    let keystore_root = temp_dir.path();

    let alice_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
    let bob_kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE";

    let alice_pk = build_test_public_key("alice@example.com", alice_kid);
    let bob_pk = build_test_public_key("bob@example.com", bob_kid);

    save_public_key(keystore_root, "alice@example.com", alice_kid, &alice_pk).unwrap();
    save_public_key(keystore_root, "bob@example.com", bob_kid, &bob_pk).unwrap();

    set_active_kid("alice@example.com", alice_kid, keystore_root).unwrap();
    set_active_kid("bob@example.com", bob_kid, keystore_root).unwrap();

    let recipients = vec![
        "alice@example.com".to_string(),
        "bob@example.com".to_string(),
    ];

    let result = load_public_keys_for_member_handles(keystore_root, &recipients).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].protected.subject_handle, "alice@example.com");
    assert_eq!(result[1].protected.subject_handle, "bob@example.com");
}
