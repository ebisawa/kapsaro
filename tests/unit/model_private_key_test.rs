// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::test_utils::{ALICE_MEMBER_ID, BOB_MEMBER_ID, TEST_MEMBER_ID};
use secretenv::model::identifiers::private_key::PROTECTION_METHOD_SSHSIG_ED25519_HKDF_SHA256;
use secretenv::model::private_key::*;

#[test]
fn test_private_key_deserialization() {
    let json_value = serde_json::json!({
        "protected": {
            "format": secretenv::model::identifiers::format::PRIVATE_KEY_V4,
            "member_id": "alice@example.com",
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "alg": {
                "kdf": PROTECTION_METHOD_SSHSIG_ED25519_HKDF_SHA256,
                "fpr": "SHA256:ABCDEFGH123456789",
                "salt": "c2FsdA",
                "aead": secretenv::model::identifiers::alg::AEAD_XCHACHA20_POLY1305
            },
            "created_at": "2024-01-15T00:00:00Z",
            "expires_at": "2025-01-15T00:00:00Z"
        },
        "encrypted": {
            "nonce": "bm9uY2U",
            "ct": "Y3QNCg"
        }
    });
    let json_str = serde_json::to_string(&json_value).expect("serialization failed");

    let pk: PrivateKey = serde_json::from_str(&json_str).expect("deserialization failed");

    assert_eq!(
        pk.protected.format,
        secretenv::model::identifiers::format::PRIVATE_KEY_V4
    );
    assert_eq!(pk.protected.member_id, ALICE_MEMBER_ID);
    assert_eq!(pk.protected.kid, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD");
    match &pk.protected.alg {
        PrivateKeyAlgorithm::SshSig { fpr, aead, .. } => {
            assert_eq!(fpr, "SHA256:ABCDEFGH123456789");
            assert_eq!(
                aead,
                secretenv::model::identifiers::alg::AEAD_XCHACHA20_POLY1305
            );
        }
        _ => panic!("Expected SshSig variant"),
    }
}

#[test]
fn test_private_key_serialization() {
    let pk = PrivateKey {
        protected: PrivateKeyProtected {
            format: secretenv::model::identifiers::format::PRIVATE_KEY_V4.to_string(),
            member_id: BOB_MEMBER_ID.to_string(),
            kid: "4Z8N6K1W3Q7RT5YH9M2PC4XV8D1B6FJA".to_string(),
            alg: PrivateKeyAlgorithm::SshSig {
                fpr: "SHA256:TESTFPR123".to_string(),
                salt: "c2FsdA".to_string(),
                aead: secretenv::model::identifiers::alg::AEAD_XCHACHA20_POLY1305.to_string(),
            },
            created_at: "2024-01-15T00:00:00Z".to_string(),
            expires_at: "2025-01-15T00:00:00Z".to_string(),
        },
        encrypted: EncryptedData {
            nonce: "bm9uY2U".to_string(),
            ct: "Y3Q".to_string(),
        },
    };

    let json_value = serde_json::to_value(&pk).expect("serialization failed");

    assert_eq!(
        json_value["protected"]["format"],
        secretenv::model::identifiers::format::PRIVATE_KEY_V4
    );
    assert_eq!(json_value["protected"]["member_id"], BOB_MEMBER_ID);
    assert_eq!(
        json_value["protected"]["alg"]["kdf"],
        PROTECTION_METHOD_SSHSIG_ED25519_HKDF_SHA256
    );
}

#[test]
fn test_private_key_plaintext_serialization() {
    let plaintext = PrivateKeyPlaintext {
        keys: IdentityKeysPrivate {
            kem: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: secretenv::model::identifiers::jwk::CRV_X25519.to_string(),
                x: "cHVibGlja2V5".to_string(),
                d: "cHJpdmF0ZWtleQ".to_string(),
            },
            sig: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: secretenv::model::identifiers::jwk::CRV_ED25519.to_string(),
                x: "c2lncHVi".to_string(),
                d: "c2lncHJpdg".to_string(),
            },
        },
    };

    let json_value = serde_json::to_value(&plaintext).expect("serialization failed");

    assert_eq!(json_value["keys"]["kem"]["kty"], "OKP");
    assert_eq!(
        json_value["keys"]["kem"]["crv"],
        secretenv::model::identifiers::jwk::CRV_X25519
    );
    assert_eq!(json_value["keys"]["sig"]["kty"], "OKP");
    assert_eq!(
        json_value["keys"]["sig"]["crv"],
        secretenv::model::identifiers::jwk::CRV_ED25519
    );
}

#[test]
fn test_private_key_roundtrip() {
    let original = PrivateKey {
        protected: PrivateKeyProtected {
            format: secretenv::model::identifiers::format::PRIVATE_KEY_V4.to_string(),
            member_id: TEST_MEMBER_ID.to_string(),
            kid: "2C7R5M9K8D1XV4PH6T3NB2QJ9F7AK5WE".to_string(),
            alg: PrivateKeyAlgorithm::SshSig {
                fpr: "SHA256:FPR123456".to_string(),
                salt: "c2FsdHNhbHQ".to_string(),
                aead: secretenv::model::identifiers::alg::AEAD_XCHACHA20_POLY1305.to_string(),
            },
            created_at: "2024-01-01T00:00:00Z".to_string(),
            expires_at: "2025-12-31T23:59:59Z".to_string(),
        },
        encrypted: EncryptedData {
            nonce: "bm9uY2Vub25jZQ".to_string(),
            ct: "Y3RjdGN0".to_string(),
        },
    };

    // Serialize
    let json_str = serde_json::to_string(&original).expect("serialization failed");

    // Deserialize
    let deserialized: PrivateKey = serde_json::from_str(&json_str).expect("deserialization failed");

    // Compare
    assert_eq!(original.protected.format, deserialized.protected.format);
    assert_eq!(
        original.protected.member_id,
        deserialized.protected.member_id
    );
    assert_eq!(original.protected.kid, deserialized.protected.kid);
    assert_eq!(original.protected.alg, deserialized.protected.alg);
}

#[test]
fn test_private_key_plaintext_debug_redacts_secret_material() {
    let plaintext = PrivateKeyPlaintext {
        keys: IdentityKeysPrivate {
            kem: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: secretenv::model::identifiers::jwk::CRV_X25519.to_string(),
                x: "public-kem".to_string(),
                d: "private-kem".to_string(),
            },
            sig: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: secretenv::model::identifiers::jwk::CRV_ED25519.to_string(),
                x: "public-sig".to_string(),
                d: "private-sig".to_string(),
            },
        },
    };

    let debug = format!("{:?}", plaintext);

    assert!(
        !debug.contains("private-kem"),
        "private key plaintext debug output must not expose KEM secret"
    );
    assert!(
        !debug.contains("private-sig"),
        "private key plaintext debug output must not expose signature secret"
    );
    assert!(
        !debug.contains("public-kem"),
        "private key plaintext debug output must not expose nested structure"
    );
    assert!(
        debug.contains("REDACTED"),
        "private key plaintext debug output should indicate redaction"
    );
}
