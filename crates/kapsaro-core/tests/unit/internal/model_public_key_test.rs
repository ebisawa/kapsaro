// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::model::public_key::{
    Attestation, BindingClaims, GithubAccount, IdentityKeys, JwkOkpPublicKey, PublicKey,
    PublicKeyParts, PublicKeyProtected,
};
use crate::test_utils::{ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE, TEST_MEMBER_HANDLE};

#[test]
fn test_public_key_deserialization() {
    let json_str = r#"{
        "protected": {
            "format": "kapsaro:format:public-key@1",
            "subject_handle": "alice@example.com",
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "keys": {
                "kem": {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU"
                },
                "sig": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU"
                }
            },
            "attestation": {
                "method": "ssh-sign",
                "pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGPf...",
                "sig": "c2lnbmF0dXJl"
            },
            "expires_at": "2025-01-15T00:00:00Z",
            "created_at": "2024-01-15T00:00:00Z"
        },
        "signature": "c2VsZnNpZw"
    }"#;

    let pk: PublicKey = serde_json::from_str(json_str).expect("deserialization failed");

    assert_eq!(
        pk.protected.format,
        crate::model::wire::format::PUBLIC_KEY_V1
    );
    assert_eq!(pk.protected.subject_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(pk.protected.kid, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD");
    assert_eq!(pk.protected.keys.kem.kty, "OKP");
    assert_eq!(
        pk.protected.keys.kem.crv,
        crate::model::wire::jwk::CURVE_X25519
    );
    assert_eq!(
        pk.protected.attestation.method,
        crate::io::ssh::protocol::constants::ATTESTATION_METHOD_SSH_SIGN
    );
}

#[test]
fn test_public_key_serialization() {
    let pk = PublicKey {
        protected: PublicKeyProtected {
            format: crate::model::wire::format::PUBLIC_KEY_V1.to_string(),
            subject_handle: BOB_MEMBER_HANDLE.to_string(),
            kid: "4Z8N6K1W3Q7RT5YH9M2PC4XV8D1B6FJA".to_string(),
            keys: IdentityKeys {
                kem: JwkOkpPublicKey {
                    kty: "OKP".to_string(),
                    crv: crate::model::wire::jwk::CURVE_X25519.to_string(),
                    x: "dGVzdGtleQ".to_string(),
                },
                sig: JwkOkpPublicKey {
                    kty: "OKP".to_string(),
                    crv: crate::model::wire::jwk::CURVE_ED25519.to_string(),
                    x: "dGVzdGtleQ".to_string(),
                },
            },
            binding_claims: None,
            attestation: Attestation {
                method: crate::io::ssh::protocol::constants::ATTESTATION_METHOD_SSH_SIGN
                    .to_string(),
                pub_: "ssh-ed25519 AAAAC3...".to_string(),
                sig: "c2lnbmF0dXJl".to_string(),
            },
            expires_at: "2025-01-15T00:00:00Z".to_string(),
            created_at: Some("2024-01-15T00:00:00Z".to_string()),
        },
        signature: "c2VsZnNpZw".to_string(),
    };

    let json_value = serde_json::to_value(&pk).expect("serialization failed");

    assert_eq!(
        json_value["protected"]["format"],
        crate::model::wire::format::PUBLIC_KEY_V1
    );
    assert_eq!(json_value["protected"]["subject_handle"], BOB_MEMBER_HANDLE);
    assert_eq!(
        json_value["protected"]["kid"],
        "4Z8N6K1W3Q7RT5YH9M2PC4XV8D1B6FJA"
    );
}

#[test]
fn test_public_key_new_preserves_binding_claims() {
    let github_account = GithubAccount {
        id: 42,
        login: "alice".to_string(),
    };
    let public_key = PublicKey::new(PublicKeyParts {
        subject_handle: TEST_MEMBER_HANDLE.to_string(),
        kid: "6Q4T8N1R5K3VM7PH2C9XD4BJ8F6AW2YE".to_string(),
        keys: IdentityKeys {
            kem: JwkOkpPublicKey {
                kty: "OKP".to_string(),
                crv: crate::model::wire::jwk::CURVE_X25519.to_string(),
                x: "a2VtcHVi".to_string(),
            },
            sig: JwkOkpPublicKey {
                kty: "OKP".to_string(),
                crv: crate::model::wire::jwk::CURVE_ED25519.to_string(),
                x: "c2lncHVi".to_string(),
            },
        },
        binding_claims: Some(BindingClaims {
            github_account: Some(github_account.clone()),
        }),
        attestation: Attestation {
            method: crate::io::ssh::protocol::constants::ATTESTATION_METHOD_SSH_SIGN.to_string(),
            pub_: "ssh-ed25519 AAAAC3...".to_string(),
            sig: "YXR0ZXN0c2ln".to_string(),
        },
        expires_at: "2025-12-31T23:59:59Z".to_string(),
        created_at: Some("2024-01-01T00:00:00Z".to_string()),
        signature: "c2ln".to_string(),
    });

    assert_eq!(
        public_key
            .protected
            .binding_claims
            .as_ref()
            .and_then(|claims| claims.github_account.as_ref()),
        Some(&github_account)
    );
}
