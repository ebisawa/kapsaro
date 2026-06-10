// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::model::private_key::PrivateKeyAlgorithm;
use crate::model::wire::algorithm::AEAD_XCHACHA20_POLY1305;
use crate::model::wire::private_key::{
    PROTECTION_KDF_ARGON2ID_M64T3P4_HKDF_SHA256, PROTECTION_KDF_SSHSIG_ED25519_HKDF_SHA256,
};

#[test]
fn test_sshsig_variant_roundtrip() {
    let alg = PrivateKeyAlgorithm::SshSig {
        fpr: "SHA256:ABCDEFGH123456789".to_string(),
        ikm_salt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        hkdf_salt: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        aead: AEAD_XCHACHA20_POLY1305.to_string(),
    };

    let json = serde_json::to_value(&alg).expect("serialize");
    assert_eq!(json["kdf"], PROTECTION_KDF_SSHSIG_ED25519_HKDF_SHA256);
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
    assert_eq!(json["kdf"], PROTECTION_KDF_ARGON2ID_M64T3P4_HKDF_SHA256);
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
fn test_private_key_algorithm_accessors_for_sshsig() {
    let alg = PrivateKeyAlgorithm::SshSig {
        fpr: "SHA256:ABCDEFGH123456789".to_string(),
        ikm_salt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        hkdf_salt: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        aead: AEAD_XCHACHA20_POLY1305.to_string(),
    };

    assert_eq!(
        alg.ikm_salt(),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    assert_eq!(
        alg.hkdf_salt(),
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    );
    assert_eq!(alg.aead(), AEAD_XCHACHA20_POLY1305);
}

#[test]
fn test_private_key_algorithm_accessors_for_argon2id() {
    let alg = PrivateKeyAlgorithm::Argon2id {
        ikm_salt: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_string(),
        hkdf_salt: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD".to_string(),
        aead: AEAD_XCHACHA20_POLY1305.to_string(),
    };

    assert_eq!(
        alg.ikm_salt(),
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
    );
    assert_eq!(
        alg.hkdf_salt(),
        "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
    );
    assert_eq!(alg.aead(), AEAD_XCHACHA20_POLY1305);
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
