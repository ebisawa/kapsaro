// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::test_utils::{ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE};
use secretenv_core::cli_api::test_support::domain::private_key::*;
use secretenv_core::cli_api::test_support::domain::wire::private_key::PROTECTION_KDF_SSHSIG_ED25519_HKDF_SHA256;

#[test]
fn test_private_key_deserialization() {
    let json_value = serde_json::json!({
        "protected": {
            "format": secretenv_core::cli_api::test_support::domain::wire::format::PRIVATE_KEY_V7,
            "subject_handle": "alice@example.com",
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "alg": {
                "kdf": PROTECTION_KDF_SSHSIG_ED25519_HKDF_SHA256,
                "fpr": "SHA256:ABCDEFGH123456789",
                "ikm_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "hkdf_salt": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                "aead": secretenv_core::cli_api::test_support::domain::wire::algorithm::AEAD_XCHACHA20_POLY1305
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
        secretenv_core::cli_api::test_support::domain::wire::format::PRIVATE_KEY_V7
    );
    assert_eq!(pk.protected.subject_handle, ALICE_MEMBER_HANDLE);
    assert_eq!(pk.protected.kid, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD");
    match &pk.protected.alg {
        PrivateKeyAlgorithm::SshSig { fpr, aead, .. } => {
            assert_eq!(fpr, "SHA256:ABCDEFGH123456789");
            assert_eq!(
                aead,
                secretenv_core::cli_api::test_support::domain::wire::algorithm::AEAD_XCHACHA20_POLY1305
            );
        }
        _ => panic!("Expected SshSig variant"),
    }
}

#[test]
fn test_private_key_serialization() {
    let pk = PrivateKey {
        protected: PrivateKeyProtected {
            format: secretenv_core::cli_api::test_support::domain::wire::format::PRIVATE_KEY_V7.to_string(),
            subject_handle: BOB_MEMBER_HANDLE.to_string(),
            kid: "4Z8N6K1W3Q7RT5YH9M2PC4XV8D1B6FJA".to_string(),
            alg: PrivateKeyAlgorithm::SshSig {
                fpr: "SHA256:TESTFPR123".to_string(),
                ikm_salt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                hkdf_salt: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
                aead: secretenv_core::cli_api::test_support::domain::wire::algorithm::AEAD_XCHACHA20_POLY1305
                    .to_string(),
            },
            created_at: "2024-01-15T00:00:00Z".to_string(),
            expires_at: "2025-01-15T00:00:00Z".to_string(),
        },
        encrypted: PrivateKeyEncData {
            nonce: "bm9uY2U".to_string(),
            ct: "Y3Q".to_string(),
        },
    };

    let json_value = serde_json::to_value(&pk).expect("serialization failed");

    assert_eq!(
        json_value["protected"]["format"],
        secretenv_core::cli_api::test_support::domain::wire::format::PRIVATE_KEY_V7
    );
    assert_eq!(json_value["protected"]["subject_handle"], BOB_MEMBER_HANDLE);
    assert_eq!(
        json_value["protected"]["alg"]["kdf"],
        PROTECTION_KDF_SSHSIG_ED25519_HKDF_SHA256
    );
}

#[test]
fn test_private_key_plaintext_serialization() {
    let plaintext = PrivateKeyPlaintext {
        keys: IdentityKeysPrivate {
            kem: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: secretenv_core::cli_api::test_support::domain::wire::jwk::CURVE_X25519
                    .to_string(),
                x: "cHVibGlja2V5".to_string(),
                d: "cHJpdmF0ZWtleQ".to_string(),
            },
            sig: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: secretenv_core::cli_api::test_support::domain::wire::jwk::CURVE_ED25519
                    .to_string(),
                x: "c2lncHVi".to_string(),
                d: "c2lncHJpdg".to_string(),
            },
        },
    };

    let json_value = serde_json::to_value(&plaintext).expect("serialization failed");

    assert_eq!(json_value["keys"]["kem"]["kty"], "OKP");
    assert_eq!(
        json_value["keys"]["kem"]["crv"],
        secretenv_core::cli_api::test_support::domain::wire::jwk::CURVE_X25519
    );
    assert_eq!(json_value["keys"]["sig"]["kty"], "OKP");
    assert_eq!(
        json_value["keys"]["sig"]["crv"],
        secretenv_core::cli_api::test_support::domain::wire::jwk::CURVE_ED25519
    );
}

#[test]
fn test_private_key_plaintext_debug_redacts_secret_material() {
    let plaintext = PrivateKeyPlaintext {
        keys: IdentityKeysPrivate {
            kem: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: secretenv_core::cli_api::test_support::domain::wire::jwk::CURVE_X25519
                    .to_string(),
                x: "public-kem".to_string(),
                d: "private-kem".to_string(),
            },
            sig: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: secretenv_core::cli_api::test_support::domain::wire::jwk::CURVE_ED25519
                    .to_string(),
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

#[test]
fn test_jwk_okp_private_key_debug_redacts_secret_component() {
    let key = JwkOkpPrivateKey {
        kty: "OKP".to_string(),
        crv: secretenv_core::cli_api::test_support::domain::wire::jwk::CURVE_ED25519.to_string(),
        x: "public-key".to_string(),
        d: "private-key".to_string(),
    };

    let debug = format!("{:?}", key);

    assert!(debug.contains("public-key"));
    assert!(!debug.contains("private-key"));
    assert!(debug.contains("REDACTED"));
}

#[test]
fn test_identity_keys_private_debug_redacts_nested_keys() {
    let keys = IdentityKeysPrivate {
        kem: JwkOkpPrivateKey {
            kty: "OKP".to_string(),
            crv: secretenv_core::cli_api::test_support::domain::wire::jwk::CURVE_X25519.to_string(),
            x: "public-kem".to_string(),
            d: "private-kem".to_string(),
        },
        sig: JwkOkpPrivateKey {
            kty: "OKP".to_string(),
            crv: secretenv_core::cli_api::test_support::domain::wire::jwk::CURVE_ED25519
                .to_string(),
            x: "public-sig".to_string(),
            d: "private-sig".to_string(),
        },
    };

    let debug = format!("{:?}", keys);

    assert!(!debug.contains("public-kem"));
    assert!(!debug.contains("private-kem"));
    assert!(!debug.contains("public-sig"));
    assert!(!debug.contains("private-sig"));
    assert!(debug.contains("REDACTED"));
}

#[test]
fn test_private_key_new_preserves_parts() {
    let protected = PrivateKeyProtected {
        format: secretenv_core::cli_api::test_support::domain::wire::format::PRIVATE_KEY_V7.to_string(),
        subject_handle: ALICE_MEMBER_HANDLE.to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        alg: PrivateKeyAlgorithm::Argon2id {
            ikm_salt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            hkdf_salt: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
            aead: secretenv_core::cli_api::test_support::domain::wire::algorithm::AEAD_XCHACHA20_POLY1305
                .to_string(),
        },
        created_at: "2024-01-15T00:00:00Z".to_string(),
        expires_at: "2025-01-15T00:00:00Z".to_string(),
    };
    let encrypted = PrivateKeyEncData {
        nonce: "bm9uY2U".to_string(),
        ct: "Y3Q".to_string(),
    };

    let key = PrivateKey::new(protected.clone(), encrypted.clone());

    assert_eq!(key.protected, protected);
    assert_eq!(key.encrypted, encrypted);
}
