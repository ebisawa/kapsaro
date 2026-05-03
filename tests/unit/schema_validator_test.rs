// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for JSON Schema validator

use crate::keygen_helpers::build_dummy_public_key;
use secretenv::format::schema::validator::Validator;
use secretenv::model::identifiers::hpke;
use secretenv::support::codec::base64_public::encode_base64url_nopad;

#[test]
fn test_validator_creation() {
    let validator = Validator::new();
    assert!(
        validator.is_ok(),
        "Validator should be created successfully"
    );
}

#[test]
fn test_load_main_schema_uses_stable_metadata() {
    let schema = Validator::load_schema_from_paths("secretenv_schema.json")
        .expect("Main schema should be loadable");

    assert_stable_schema_metadata(&schema, "secretenv.schema.json", "secretenv schema");
}

#[test]
fn test_load_trust_schema_uses_stable_metadata() {
    let schema = Validator::load_schema_from_paths("secretenv_trust_local_schema.json")
        .expect("Trust schema should be loadable with the aligned filename");

    assert_stable_schema_metadata(
        &schema,
        "secretenv.trust.local.schema.json",
        "secretenv local trust store schema",
    );
}

fn assert_stable_schema_metadata(
    schema: &serde_json::Value,
    expected_id: &str,
    expected_title: &str,
) {
    let id = schema.get("$id").and_then(serde_json::Value::as_str);
    let title = schema.get("title").and_then(serde_json::Value::as_str);

    assert_eq!(id, Some(expected_id));
    assert_eq!(title, Some(expected_title));
    for value in [expected_id, expected_title] {
        assert!(!contains_schema_version_or_revision(value));
    }
}

fn contains_schema_version_or_revision(value: &str) -> bool {
    value
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(is_version_or_revision_token)
}

fn is_version_or_revision_token(token: &str) -> bool {
    token == "rev" || is_version_token(token)
}

fn is_version_token(token: &str) -> bool {
    let Some(digits) = token.strip_prefix('v') else {
        return false;
    };
    !digits.is_empty() && digits.chars().all(|ch| ch.is_ascii_digit())
}

#[test]
fn test_validate_public_key_basic() {
    let validator = Validator::new().unwrap();
    // PublicKey requires: protected (format, subject_handle, kid, identity, attestation, expires_at), signature.
    let valid_public_key = serde_json::json!({
        "protected": {
            "format": secretenv::model::identifiers::format::PUBLIC_KEY_V5,
            "subject_handle": "alice@example.com",
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
fn test_validate_public_key_accepts_valid_github_login() {
    let validator = Validator::new().unwrap();
    let public_key = build_public_key_with_github_login("alice-gh");

    let result = validator.validate_public_key(&public_key);

    assert!(
        result.is_ok(),
        "Valid GitHub login should pass schema validation: {:?}",
        result
    );
}

#[test]
fn test_validate_public_key_rejects_invalid_github_login() {
    let validator = Validator::new().unwrap();

    for login in ["../alice", "alice/keys", "alice?tab=keys", "alice#keys"] {
        let public_key = build_public_key_with_github_login(login);
        let result = validator.validate_public_key(&public_key);
        assert!(result.is_err(), "should reject login: {}", login);
    }
}

#[test]
fn test_schema_error_message_describes_invalid_field_without_raw_value() {
    let validator = Validator::new().unwrap();
    let invalid_login = "alice#keys";
    let public_key = build_public_key_with_github_login(invalid_login);

    let error = validator.validate_public_key(&public_key).unwrap_err();
    let message = error.format_user_message();

    assert!(message.contains("Invalid secretenv document"));
    assert!(message.contains("protected.binding_claims.github_account.login"));
    assert!(message.contains("does not match"));
    assert!(!message.contains("E_SCHEMA_INVALID"));
    assert!(!message.contains("schema"));
    assert!(!message.contains(invalid_login));
}

fn build_public_key_with_github_login(login: &str) -> serde_json::Value {
    serde_json::json!({
        "protected": {
            "format": secretenv::model::identifiers::format::PUBLIC_KEY_V5,
            "subject_handle": "alice@example.com",
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
            "binding_claims": {
                "github_account": {
                    "id": 12345,
                    "login": login
                }
            },
            "expires_at": "2027-01-01T00:00:00Z"
        },
        "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    })
}

#[test]
fn test_validate_private_key_basic() {
    let validator = Validator::new().unwrap();
    let ikm_salt = encode_base64url_nopad(&[0u8; 32]);
    let hkdf_salt = encode_base64url_nopad(&[1u8; 32]);
    // PrivateKey external format includes protected and encrypted sections.
    let valid_private_key = serde_json::json!({
        "protected": {
            "format": secretenv::model::identifiers::format::PRIVATE_KEY_V6,
            "subject_handle": "alice@example.com",
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "alg": {
                "kdf": secretenv::model::identifiers::private_key::PROTECTION_METHOD_SSHSIG_ED25519_HKDF_SHA256,
                "fpr": "SHA256:abcdef1234567890",
                "ikm_salt": ikm_salt,
                "hkdf_salt": hkdf_salt,
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
    let ikm_salt = encode_base64url_nopad(&[0u8; 32]);
    let hkdf_salt = encode_base64url_nopad(&[1u8; 32]);
    let valid_private_key = serde_json::json!({
        "protected": {
            "format": secretenv::model::identifiers::format::PRIVATE_KEY_V6,
            "subject_handle": "alice@example.com",
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "alg": {
                "kdf": secretenv::model::identifiers::private_key::PROTECTION_METHOD_ARGON2ID_M64T3P4_HKDF_SHA256,
                "ikm_salt": ikm_salt,
                "hkdf_salt": hkdf_salt,
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
    let ikm_salt = encode_base64url_nopad(&[0u8; 32]);
    let hkdf_salt = encode_base64url_nopad(&[1u8; 32]);
    let invalid_private_key = serde_json::json!({
        "protected": {
            "format": secretenv::model::identifiers::format::PRIVATE_KEY_V6,
            "subject_handle": "alice@example.com",
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "alg": {
                "kdf": secretenv::model::identifiers::private_key::PROTECTION_METHOD_ARGON2ID_M64T3P4_HKDF_SHA256,
                "m": 47104,
                "t": 1,
                "p": 1,
                "ikm_salt": ikm_salt,
                "hkdf_salt": hkdf_salt,
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
    // File encryption documents require protected metadata, payload, wraps, and signature.
    let sid = "123e4567-e89b-12d3-a456-426614174000";
    let valid_file_enc_doc = serde_json::json!({
        "protected": {
            "format": secretenv::model::identifiers::format::FILE_ENC_V4,
            "sid": sid,
            "payload": {
                "protected": {
                    "format": secretenv::model::identifiers::format::FILE_PAYLOAD_V4,
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
                "recipient_handle": "alice@example.com",
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
            "signer_pub": serde_json::to_value(build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD")).unwrap(),
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
fn test_validator_allows_member_handle_without_at_in_wrap_rid() {
    let validator = Validator::new().unwrap();

    // Regression test:
    // - CLI validation allows member_handle without '@' (e.g. GitHub login like "ebisawa")
    // - JSON schema should accept the same to avoid runtime validation failures
    let sid = "123e4567-e89b-12d3-a456-426614174000";
    let valid_file_enc_doc = serde_json::json!({
        "protected": {
            "format": secretenv::model::identifiers::format::FILE_ENC_V4,
            "sid": sid,
            "payload": {
                "protected": {
                    "format": secretenv::model::identifiers::format::FILE_PAYLOAD_V4,
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
                "recipient_handle": "ebisawa",
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
            "signer_pub": serde_json::to_value(build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD")).unwrap(),
            "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
        }
    });

    let result = validator.validate_file_enc_document(&valid_file_enc_doc);
    assert!(
        result.is_ok(),
        "Schema should allow member_handle without '@' in wrap.recipient_handle: {:?}",
        result
    );
}
