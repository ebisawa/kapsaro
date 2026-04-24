// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv::model::identifiers::alg::AEAD_XCHACHA20_POLY1305;
use secretenv::model::identifiers::private_key::{
    PROTECTION_METHOD_ARGON2ID_M64T3P4_HKDF_SHA256, PROTECTION_METHOD_SSHSIG_ED25519_HKDF_SHA256,
};
use secretenv::model::private_key::*;

#[test]
fn test_sshsig_variant_roundtrip() {
    let alg = PrivateKeyAlgorithm::SshSig {
        fpr: "SHA256:ABCDEFGH123456789".to_string(),
        ikm_salt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        hkdf_salt: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        aead: AEAD_XCHACHA20_POLY1305.to_string(),
    };

    let json = serde_json::to_value(&alg).expect("serialize");
    assert_eq!(json["kdf"], PROTECTION_METHOD_SSHSIG_ED25519_HKDF_SHA256);
    assert_eq!(json["fpr"], "SHA256:ABCDEFGH123456789");
    assert_eq!(
        json["ikm_salt"],
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    assert_eq!(
        json["hkdf_salt"],
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    );
    assert_eq!(json["aead"], AEAD_XCHACHA20_POLY1305);

    let deserialized: PrivateKeyAlgorithm = serde_json::from_value(json).expect("deserialize");
    assert_eq!(alg, deserialized);
}

#[test]
fn test_argon2id_variant_roundtrip() {
    let alg = PrivateKeyAlgorithm::Argon2id {
        ikm_salt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        hkdf_salt: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        aead: AEAD_XCHACHA20_POLY1305.to_string(),
    };

    let json = serde_json::to_value(&alg).expect("serialize");
    assert_eq!(json["kdf"], PROTECTION_METHOD_ARGON2ID_M64T3P4_HKDF_SHA256);
    assert_eq!(
        json["ikm_salt"],
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    assert_eq!(
        json["hkdf_salt"],
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    );
    assert_eq!(json["aead"], AEAD_XCHACHA20_POLY1305);

    let deserialized: PrivateKeyAlgorithm = serde_json::from_value(json).expect("deserialize");
    assert_eq!(alg, deserialized);
}

#[test]
fn test_argon2id_variant_rejects_legacy_params() {
    let json = serde_json::json!({
        "kdf": PROTECTION_METHOD_ARGON2ID_M64T3P4_HKDF_SHA256,
        "m": 47104,
        "t": 1,
        "p": 1,
        "ikm_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "hkdf_salt": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "aead": AEAD_XCHACHA20_POLY1305
    });

    let result = serde_json::from_value::<PrivateKeyAlgorithm>(json);
    assert!(result.is_err(), "legacy argon2 params must be rejected");
}

#[test]
fn test_unknown_kdf_fails() {
    let json = serde_json::json!({
        "kdf": "unknown-kdf-method",
        "ikm_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "hkdf_salt": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "aead": AEAD_XCHACHA20_POLY1305
    });

    let result = serde_json::from_value::<PrivateKeyAlgorithm>(json);
    assert!(result.is_err());
}

#[test]
fn test_existing_private_key_document_roundtrip() {
    let doc = PrivateKey {
        protected: PrivateKeyProtected {
            format: secretenv::model::identifiers::format::PRIVATE_KEY_V5.to_string(),
            member_id: "alice@example.com".to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
            alg: PrivateKeyAlgorithm::SshSig {
                fpr: "SHA256:ABCDEFGH123456789".to_string(),
                ikm_salt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                hkdf_salt: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
                aead: AEAD_XCHACHA20_POLY1305.to_string(),
            },
            created_at: "2024-01-15T00:00:00Z".to_string(),
            expires_at: "2025-01-15T00:00:00Z".to_string(),
        },
        encrypted: PrivateKeyEncData {
            nonce: "bm9uY2U".to_string(),
            ct: "Y3QNCg".to_string(),
        },
    };

    let json_str = serde_json::to_string(&doc).expect("serialize");
    let deserialized: PrivateKey = serde_json::from_str(&json_str).expect("deserialize");

    assert_eq!(doc, deserialized);

    // Verify wire format has "kdf" field for backward compatibility
    let json_value: serde_json::Value = serde_json::from_str(&json_str).expect("parse json");
    assert_eq!(
        json_value["protected"]["alg"]["kdf"],
        PROTECTION_METHOD_SSHSIG_ED25519_HKDF_SHA256
    );
}
