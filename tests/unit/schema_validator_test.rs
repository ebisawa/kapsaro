// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for JSON Schema validator

use secretenv::format::schema::validator::Validator;
use secretenv::model::identifiers::hpke;

#[test]
fn test_validator_creation() {
    let validator = Validator::new();
    assert!(
        validator.is_ok(),
        "Validator v3 should be created successfully"
    );
}

#[test]
fn test_load_trust_schema_with_aligned_filename() {
    let schema = Validator::load_schema_from_paths("secretenv_trust_local_schema.json")
        .expect("Trust schema should be loadable with the aligned filename");
    assert!(
        schema
            .get("$id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|id| id == "secretenv.trust.local.schema.v2.json"),
        "Trust schema should expose the aligned schema id"
    );
}

#[test]
fn test_validate_public_key_basic() {
    let validator = Validator::new().unwrap();
    // v3 schema requires: protected (format, member_id, kid, identity, attestation, expires_at), signature
    let valid_public_key = serde_json::json!({
        "protected": {
            "format": secretenv::model::identifiers::format::PUBLIC_KEY_V4,
            "member_id": "alice@example.com",
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "identity": {
                "keys": {
                    "kem": {
                        "kty": "OKP",
                        "crv": secretenv::model::identifiers::jwk::CRV_X25519,
                        "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    },
                    "sig": {
                        "kty": "OKP",
                        "crv": secretenv::model::identifiers::jwk::CRV_ED25519,
                        "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    }
                },
                "attestation": {
                    "method": "ssh-sign",
                    "pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
                }
            },
            "expires_at": "2027-01-01T00:00:00Z"
        },
        "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    });

    let result = validator.validate_public_key(&valid_public_key);
    assert!(
        result.is_ok(),
        "Valid public key v3 should pass validation: {:?}",
        result
    );
}

#[test]
fn test_validate_private_key_basic() {
    let validator = Validator::new().unwrap();
    // v3 schema (Rev11): external format with protection and encrypted fields
    let valid_private_key = serde_json::json!({
        "protected": {
            "format": secretenv::model::identifiers::format::PRIVATE_KEY_V4,
            "member_id": "alice@example.com",
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "alg": {
                "kdf": secretenv::model::identifiers::private_key::PROTECTION_METHOD_SSHSIG_ED25519_HKDF_SHA256,
                "fpr": "SHA256:abcdef1234567890",
                "salt": "AAAAAAAAAAAAAAAAAAAAAA",
                "aead": secretenv::model::identifiers::alg::AEAD_XCHACHA20_POLY1305
            },
            "created_at": "2026-01-14T00:00:00Z",
            "expires_at": "2027-01-14T00:00:00Z"
        },
        "encrypted": {
            "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "ct": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        }
    });

    let result = validator.validate_private_key(&valid_private_key);
    assert!(
        result.is_ok(),
        "Valid private key v3 should pass validation: {:?}",
        result
    );
}

#[test]
fn test_validate_private_key_argon2id_without_params() {
    let validator = Validator::new().unwrap();
    let valid_private_key = serde_json::json!({
        "protected": {
            "format": secretenv::model::identifiers::format::PRIVATE_KEY_V4,
            "member_id": "alice@example.com",
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "alg": {
                "kdf": secretenv::model::identifiers::private_key::PROTECTION_METHOD_ARGON2ID_HKDF_SHA256,
                "salt": "AAAAAAAAAAAAAAAAAAAAAA",
                "aead": secretenv::model::identifiers::alg::AEAD_XCHACHA20_POLY1305
            },
            "created_at": "2026-01-14T00:00:00Z",
            "expires_at": "2027-01-14T00:00:00Z"
        },
        "encrypted": {
            "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "ct": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        }
    });

    let result = validator.validate_private_key(&valid_private_key);
    assert!(
        result.is_ok(),
        "Argon2id private key v3 should pass validation: {:?}",
        result
    );
}

#[test]
fn test_validate_private_key_argon2id_rejects_legacy_params() {
    let validator = Validator::new().unwrap();
    let invalid_private_key = serde_json::json!({
        "protected": {
            "format": secretenv::model::identifiers::format::PRIVATE_KEY_V4,
            "member_id": "alice@example.com",
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "alg": {
                "kdf": secretenv::model::identifiers::private_key::PROTECTION_METHOD_ARGON2ID_HKDF_SHA256,
                "m": 47104,
                "t": 1,
                "p": 1,
                "salt": "AAAAAAAAAAAAAAAAAAAAAA",
                "aead": secretenv::model::identifiers::alg::AEAD_XCHACHA20_POLY1305
            },
            "created_at": "2026-01-14T00:00:00Z",
            "expires_at": "2027-01-14T00:00:00Z"
        },
        "encrypted": {
            "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "ct": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        }
    });

    let result = validator.validate_private_key(&invalid_private_key);
    assert!(
        result.is_err(),
        "Legacy argon2 params must fail schema validation"
    );
}

#[test]
fn test_validate_file_enc_document_basic() {
    let validator = Validator::new().unwrap();
    // v3 schema requires: protected { format, sid, payload, wrap, created_at, updated_at }, signature
    // payload is envelope: { protected { format, sid, alg }, encrypted { nonce, ct } }
    // wrap_item v3 requires: rid, kid, alg, enc, ct
    let sid = "123e4567-e89b-12d3-a456-426614174000";
    let valid_file_enc_doc = serde_json::json!({
        "protected": {
            "format": secretenv::model::identifiers::format::FILE_ENC_V3,
            "sid": sid,
            "payload": {
                "protected": {
                    "format": secretenv::model::identifiers::format::FILE_PAYLOAD_V3,
                    "sid": sid,
                    "alg": {
                        "aead": secretenv::model::identifiers::alg::AEAD_XCHACHA20_POLY1305
                    }
                },
                "encrypted": {
                    "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "ct": "AAAAAAAAAAAAAAAA"
                }
            },
            "wrap": [{
                "rid": "alice@example.com",
                "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
                "alg": hpke::ALG_HPKE_32_1_3,
                "enc": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "ct": "AAAAAAAAAAAAAAAA"
            }],
            "created_at": "2026-01-14T00:00:00Z",
            "updated_at": "2026-01-14T00:00:00Z"
        },
        "signature": {
            "alg": secretenv::model::identifiers::alg::SIGNATURE_ED25519,
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
        }
    });

    let result = validator.validate_file_enc_document(&valid_file_enc_doc);
    assert!(
        result.is_ok(),
        "Valid file secret v3 should pass validation: {:?}",
        result
    );
}

#[test]
fn test_validator_allows_member_id_without_at_in_wrap_rid() {
    let validator = Validator::new().unwrap();

    // Regression test:
    // - CLI validation allows member_id without '@' (e.g. GitHub login like "ebisawa")
    // - v3 JSON schema should accept the same to avoid runtime validation failures
    let sid = "123e4567-e89b-12d3-a456-426614174000";
    let valid_file_enc_doc = serde_json::json!({
        "protected": {
            "format": secretenv::model::identifiers::format::FILE_ENC_V3,
            "sid": sid,
            "payload": {
                "protected": {
                    "format": secretenv::model::identifiers::format::FILE_PAYLOAD_V3,
                    "sid": sid,
                    "alg": {
                        "aead": secretenv::model::identifiers::alg::AEAD_XCHACHA20_POLY1305
                    }
                },
                "encrypted": {
                    "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "ct": "AAAAAAAAAAAAAAAA"
                }
            },
            "wrap": [{
                "rid": "ebisawa",
                "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
                "alg": hpke::ALG_HPKE_32_1_3,
                "enc": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "ct": "AAAAAAAAAAAAAAAA"
            }],
            "created_at": "2026-01-14T00:00:00Z",
            "updated_at": "2026-01-14T00:00:00Z"
        },
        "signature": {
            "alg": secretenv::model::identifiers::alg::SIGNATURE_ED25519,
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
        }
    });

    let result = validator.validate_file_enc_document(&valid_file_enc_doc);
    assert!(
        result.is_ok(),
        "Schema should allow member_id without '@' in wrap.rid: {:?}",
        result
    );
}
