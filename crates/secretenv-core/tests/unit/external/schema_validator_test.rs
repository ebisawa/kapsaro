// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for JSON Schema validator

use crate::keygen_helpers::build_dummy_public_key;
use secretenv_core::cli_api::test_support::domain::wire::algorithm;
use secretenv_core::cli_api::test_support::helpers::codec::base64_public::encode_base64url_nopad;
use secretenv_core::cli_api::test_support::wire::schema::validator::{
    load_embedded_validator, SchemaTarget, Validator,
};

const B64URL_24: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const B64URL_32: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const B64URL_48: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const B64URL_64: &str =
    "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ";
const B64URL_VARIABLE_MOD2: &str = "AA";
const B64URL_VARIABLE_MOD3: &str = "AAA";
const B64URL_VARIABLE_MOD1: &str = "A";
const B64URL_VARIABLE_NON_CANONICAL_MOD2: &str = "AB";
const B64URL_VARIABLE_NON_CANONICAL_MOD3: &str = "AAB";

#[test]
fn test_target_schemas_use_stable_metadata() {
    for (target, expected_id, expected_title) in [
        (
            SchemaTarget::PublicKey,
            "secretenv.public.key.schema.json",
            "secretenv public key schema",
        ),
        (
            SchemaTarget::PrivateKey,
            "secretenv.private.key.schema.json",
            "secretenv private key schema",
        ),
        (
            SchemaTarget::FileEnc,
            "secretenv.file.enc.schema.json",
            "secretenv file enc schema",
        ),
        (
            SchemaTarget::ArtifactSignature,
            "secretenv.artifact.signature.schema.json",
            "secretenv artifact signature schema",
        ),
        (
            SchemaTarget::LocalTrust,
            "secretenv.local.trust.schema.json",
            "secretenv local trust schema",
        ),
    ] {
        let schema = Validator::load_schema_from_paths(target.filename())
            .expect("target schema should be loadable");

        assert_stable_schema_metadata(&schema, expected_id, expected_title);
    }
}

#[test]
fn test_kv_schema_uses_stable_metadata() {
    let schema = Validator::load_schema_from_paths(SchemaTarget::KvHead.filename())
        .expect("KV schema should be loadable");

    assert_stable_schema_metadata(
        &schema,
        "secretenv.kv.enc.schema.json",
        "secretenv kv enc schema",
    );
}

#[test]
fn test_embedded_target_validators_compile() {
    for target in [
        SchemaTarget::PublicKey,
        SchemaTarget::PrivateKey,
        SchemaTarget::FileEnc,
        SchemaTarget::KvHead,
        SchemaTarget::KvWrap,
        SchemaTarget::KvEntry,
        SchemaTarget::ArtifactSignature,
        SchemaTarget::LocalTrust,
    ] {
        load_embedded_validator(target).expect("embedded target validator should compile");
    }
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
fn test_validate_public_key_accepts_valid_github_login() {
    let validator = Validator::for_target(SchemaTarget::PublicKey).unwrap();
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
    let validator = Validator::for_target(SchemaTarget::PublicKey).unwrap();

    for login in ["../alice", "alice/keys", "alice?tab=keys", "alice#keys"] {
        let public_key = build_public_key_with_github_login(login);
        let result = validator.validate_public_key(&public_key);
        assert!(result.is_err(), "should reject login: {}", login);
    }
}

#[test]
fn test_validate_public_key_rejects_wrong_crypto_field_lengths() {
    let validator = Validator::for_target(SchemaTarget::PublicKey).unwrap();

    for (field, path, value) in [
        (
            "kem.x",
            &["protected", "identity", "keys", "kem", "x"][..],
            "AAAAAAAAAAAAAAAAAAAAAA",
        ),
        (
            "sig.x",
            &["protected", "identity", "keys", "sig", "x"][..],
            "AAAAAAAAAAAAAAAAAAAAAA",
        ),
        (
            "attestation.sig",
            &["protected", "identity", "attestation", "sig"][..],
            "AAAAAAAAAAAAAAAAAAAAAA",
        ),
        ("signature", &["signature"][..], "AAAAAAAAAAAAAAAAAAAAAA"),
    ] {
        let mut public_key = build_public_key_with_github_login("alice-gh");
        set_json_path(&mut public_key, path, value);

        let result = validator.validate_public_key(&public_key);

        assert!(result.is_err(), "should reject wrong {field} length");
    }
}

#[test]
fn test_validate_public_key_rejects_non_canonical_fixed_length_tail_bits() {
    let validator = Validator::for_target(SchemaTarget::PublicKey).unwrap();
    let mut public_key = build_public_key_with_github_login("alice-gh");
    set_json_path(
        &mut public_key,
        &["protected", "identity", "keys", "kem", "x"],
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
    );

    let result = validator.validate_public_key(&public_key);

    assert!(result.is_err(), "should reject non-canonical kem.x");
}

#[test]
fn test_schema_error_message_describes_invalid_field_without_raw_value() {
    let validator = Validator::for_target(SchemaTarget::PublicKey).unwrap();
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

fn set_json_path(value: &mut serde_json::Value, path: &[&str], replacement: &str) {
    let mut current = value;
    for segment in &path[..path.len() - 1] {
        current = current
            .get_mut(*segment)
            .expect("test fixture path should exist");
    }
    current[path[path.len() - 1]] = serde_json::Value::String(replacement.to_string());
}

fn build_public_key_with_github_login(login: &str) -> serde_json::Value {
    serde_json::json!({
        "protected": {
            "format": secretenv_core::cli_api::test_support::domain::wire::format::PUBLIC_KEY_V6,
            "subject_handle": "alice@example.com",
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "identity": {
                "keys": {
                    "kem": {
                        "kty": "OKP",
                        "crv": secretenv_core::cli_api::test_support::domain::wire::jwk::CURVE_X25519,
                        "x": B64URL_32
                    },
                    "sig": {
                        "kty": "OKP",
                        "crv": secretenv_core::cli_api::test_support::domain::wire::jwk::CURVE_ED25519,
                        "x": B64URL_32
                    }
                },
                "attestation": {
                    "method": "ssh-sign",
                    "pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "sig": B64URL_64
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
        "signature": B64URL_64
    })
}

#[test]
fn test_validate_private_key_basic() {
    let validator = Validator::for_target(SchemaTarget::PrivateKey).unwrap();
    let ikm_salt = encode_base64url_nopad(&[0u8; 32]);
    let hkdf_salt = encode_base64url_nopad(&[1u8; 32]);
    // PrivateKey external format includes protected and encrypted sections.
    let valid_private_key = serde_json::json!({
        "protected": {
            "format": secretenv_core::cli_api::test_support::domain::wire::format::PRIVATE_KEY_V7,
            "subject_handle": "alice@example.com",
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "alg": {
                "kdf": secretenv_core::cli_api::test_support::domain::wire::private_key::PROTECTION_KDF_SSHSIG_ED25519_HKDF_SHA256,
                "fpr": "SHA256:abcdef1234567890",
                "ikm_salt": ikm_salt,
                "hkdf_salt": hkdf_salt,
                "aead": secretenv_core::cli_api::test_support::domain::wire::algorithm::AEAD_XCHACHA20_POLY1305
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
    let validator = Validator::for_target(SchemaTarget::PrivateKey).unwrap();
    let ikm_salt = encode_base64url_nopad(&[0u8; 32]);
    let hkdf_salt = encode_base64url_nopad(&[1u8; 32]);
    let valid_private_key = serde_json::json!({
        "protected": {
            "format": secretenv_core::cli_api::test_support::domain::wire::format::PRIVATE_KEY_V7,
            "subject_handle": "alice@example.com",
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "alg": {
                "kdf": secretenv_core::cli_api::test_support::domain::wire::private_key::PROTECTION_KDF_ARGON2ID_M64T3P4_HKDF_SHA256,
                "ikm_salt": ikm_salt,
                "hkdf_salt": hkdf_salt,
                "aead": secretenv_core::cli_api::test_support::domain::wire::algorithm::AEAD_XCHACHA20_POLY1305
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
fn test_validate_private_key_rejects_wrong_fixed_lengths() {
    let validator = Validator::for_target(SchemaTarget::PrivateKey).unwrap();

    for (field, path, value) in [
        (
            "ikm_salt",
            &["protected", "alg", "ikm_salt"][..],
            "AAAAAAAAAAAAAAAAAAAAAA",
        ),
        (
            "hkdf_salt",
            &["protected", "alg", "hkdf_salt"][..],
            "AAAAAAAAAAAAAAAAAAAAAA",
        ),
        (
            "nonce",
            &["encrypted", "nonce"][..],
            "AAAAAAAAAAAAAAAAAAAAAA",
        ),
    ] {
        let mut private_key = build_valid_private_key();
        set_json_path(&mut private_key, path, value);

        let result = validator.validate_private_key(&private_key);

        assert!(result.is_err(), "should reject wrong {field} length");
    }
}

fn build_valid_private_key() -> serde_json::Value {
    let ikm_salt = encode_base64url_nopad(&[0u8; 32]);
    let hkdf_salt = encode_base64url_nopad(&[1u8; 32]);
    serde_json::json!({
        "protected": {
            "format": secretenv_core::cli_api::test_support::domain::wire::format::PRIVATE_KEY_V7,
            "subject_handle": "alice@example.com",
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "alg": {
                "kdf": secretenv_core::cli_api::test_support::domain::wire::private_key::PROTECTION_KDF_SSHSIG_ED25519_HKDF_SHA256,
                "fpr": "SHA256:abcdef1234567890",
                "ikm_salt": ikm_salt,
                "hkdf_salt": hkdf_salt,
                "aead": secretenv_core::cli_api::test_support::domain::wire::algorithm::AEAD_XCHACHA20_POLY1305
            },
            "created_at": "2026-01-14T00:00:00Z",
            "expires_at": "2027-01-14T00:00:00Z"
        },
        "encrypted": {
            "nonce": B64URL_24,
            "ct": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        }
    })
}

#[test]
fn test_validate_private_key_accepts_canonical_variable_length_ct() {
    let validator = Validator::for_target(SchemaTarget::PrivateKey).unwrap();

    for ct in [B64URL_VARIABLE_MOD2, B64URL_VARIABLE_MOD3, B64URL_48] {
        let mut private_key = build_valid_private_key();
        set_json_path(&mut private_key, &["encrypted", "ct"], ct);

        let result = validator.validate_private_key(&private_key);

        assert!(result.is_ok(), "should accept canonical ct: {ct}");
    }
}

#[test]
fn test_validate_private_key_rejects_non_canonical_variable_length_ct() {
    let validator = Validator::for_target(SchemaTarget::PrivateKey).unwrap();

    for ct in [
        B64URL_VARIABLE_MOD1,
        B64URL_VARIABLE_NON_CANONICAL_MOD2,
        B64URL_VARIABLE_NON_CANONICAL_MOD3,
    ] {
        let mut private_key = build_valid_private_key();
        set_json_path(&mut private_key, &["encrypted", "ct"], ct);

        let result = validator.validate_private_key(&private_key);

        assert!(result.is_err(), "should reject non-canonical ct: {ct}");
    }
}

#[test]
fn test_validate_file_enc_rejects_wrong_fixed_lengths() {
    let validator = Validator::for_target(SchemaTarget::FileEnc).unwrap();

    for (field, path, value) in [
        (
            "payload nonce",
            &["protected", "payload", "encrypted", "nonce"][..],
            "AAAAAAAAAAAAAAAAAAAAAA",
        ),
        (
            "wrap enc",
            &["protected", "wrap", "0", "enc"][..],
            "AAAAAAAAAAAAAAAAAAAAAA",
        ),
        (
            "wrap ct",
            &["protected", "wrap", "0", "ct"][..],
            "AAAAAAAAAAAAAAAAAAAAAA",
        ),
        (
            "signature sig",
            &["signature", "sig"][..],
            "AAAAAAAAAAAAAAAAAAAAAA",
        ),
    ] {
        let mut file_enc = build_valid_file_enc_doc("alice@example.com");
        set_json_path_with_array(&mut file_enc, path, value);

        let result = validator.validate_file_enc_document(&file_enc);

        assert!(result.is_err(), "should reject wrong {field} length");
    }
}

#[test]
fn test_validate_file_enc_accepts_canonical_variable_length_payload_ct() {
    let validator = Validator::for_target(SchemaTarget::FileEnc).unwrap();

    for ct in [B64URL_VARIABLE_MOD2, B64URL_VARIABLE_MOD3, B64URL_48] {
        let mut file_enc = build_valid_file_enc_doc("alice@example.com");
        set_json_path_with_array(
            &mut file_enc,
            &["protected", "payload", "encrypted", "ct"],
            ct,
        );

        let result = validator.validate_file_enc_document(&file_enc);

        assert!(result.is_ok(), "should accept canonical payload ct: {ct}");
    }
}

#[test]
fn test_validate_file_enc_rejects_non_canonical_variable_length_payload_ct() {
    let validator = Validator::for_target(SchemaTarget::FileEnc).unwrap();

    for ct in [
        B64URL_VARIABLE_MOD1,
        B64URL_VARIABLE_NON_CANONICAL_MOD2,
        B64URL_VARIABLE_NON_CANONICAL_MOD3,
    ] {
        let mut file_enc = build_valid_file_enc_doc("alice@example.com");
        set_json_path_with_array(
            &mut file_enc,
            &["protected", "payload", "encrypted", "ct"],
            ct,
        );

        let result = validator.validate_file_enc_document(&file_enc);

        assert!(
            result.is_err(),
            "should reject non-canonical payload ct: {ct}"
        );
    }
}

#[test]
fn test_validate_kv_entry_accepts_canonical_variable_length_ct() {
    let validator = Validator::for_target(SchemaTarget::KvEntry).unwrap();

    for ct in [B64URL_VARIABLE_MOD2, B64URL_VARIABLE_MOD3, B64URL_48] {
        let entry = build_kv_entry_value(ct);

        let result = validator.validate_kv_entry(&entry);

        assert!(result.is_ok(), "should accept canonical entry ct: {ct}");
    }
}

#[test]
fn test_validate_kv_entry_rejects_non_canonical_variable_length_ct() {
    let validator = Validator::for_target(SchemaTarget::KvEntry).unwrap();

    for ct in [
        B64URL_VARIABLE_MOD1,
        B64URL_VARIABLE_NON_CANONICAL_MOD2,
        B64URL_VARIABLE_NON_CANONICAL_MOD3,
    ] {
        let entry = build_kv_entry_value(ct);

        let result = validator.validate_kv_entry(&entry);

        assert!(
            result.is_err(),
            "should reject non-canonical entry ct: {ct}"
        );
    }
}

fn build_kv_entry_value(ct: &str) -> serde_json::Value {
    serde_json::json!({
        "nonce": B64URL_24,
        "ct": ct
    })
}

fn set_json_path_with_array(value: &mut serde_json::Value, path: &[&str], replacement: &str) {
    let mut current = value;
    for segment in &path[..path.len() - 1] {
        current = if let Ok(index) = segment.parse::<usize>() {
            current
                .get_mut(index)
                .expect("test fixture array path should exist")
        } else {
            current
                .get_mut(*segment)
                .expect("test fixture object path should exist")
        };
    }
    current[path[path.len() - 1]] = serde_json::Value::String(replacement.to_string());
}

fn build_valid_file_enc_doc(recipient_handle: &str) -> serde_json::Value {
    let sid = "123e4567-e89b-12d3-a456-426614174000";
    serde_json::json!({
        "protected": {
            "format": secretenv_core::cli_api::test_support::domain::wire::format::FILE_ENC_V7,
            "sid": sid,
            "payload": {
                "protected": {
                    "format": secretenv_core::cli_api::test_support::domain::wire::format::FILE_PAYLOAD_V7,
                    "sid": sid,
                    "alg": { "aead": secretenv_core::cli_api::test_support::domain::wire::algorithm::AEAD_XCHACHA20_POLY1305 }
                },
                "encrypted": { "nonce": B64URL_24, "ct": B64URL_48 }
            },
            "wrap": [{
                "rh": recipient_handle,
                "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
                "alg": algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305,
                "enc": B64URL_32,
                "ct": B64URL_48
            }],
            "created_at": "2026-01-14T00:00:00Z",
            "updated_at": "2026-01-14T00:00:00Z"
        },
        "signature": {
            "alg": secretenv_core::cli_api::test_support::domain::wire::algorithm::SIGNATURE_ED25519,
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "signer_pub": serde_json::to_value(build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD")).unwrap(),
            "mac": "hmac-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "sig": B64URL_64
        }
    })
}

#[test]
fn test_validator_allows_member_handle_without_at_in_wrap_rh() {
    let validator = Validator::for_target(SchemaTarget::FileEnc).unwrap();

    // Regression test:
    // - CLI validation allows member_handle without '@' (e.g. GitHub login like "ebisawa")
    // - JSON schema should accept the same to avoid runtime validation failures
    let sid = "123e4567-e89b-12d3-a456-426614174000";
    let valid_file_enc_doc = serde_json::json!({
        "protected": {
            "format": secretenv_core::cli_api::test_support::domain::wire::format::FILE_ENC_V7,
            "sid": sid,
            "payload": {
                "protected": {
                    "format": secretenv_core::cli_api::test_support::domain::wire::format::FILE_PAYLOAD_V7,
                    "sid": sid,
                    "alg": {
                        "aead": secretenv_core::cli_api::test_support::domain::wire::algorithm::AEAD_XCHACHA20_POLY1305
                    }
                },
                "encrypted": {
                    "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "ct": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                }
            },
            "wrap": [{
                "rh": "ebisawa",
                "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
                "alg": algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305,
                "enc": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "ct": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }],
            "created_at": "2026-01-14T00:00:00Z",
            "updated_at": "2026-01-14T00:00:00Z"
        },
        "signature": {
            "alg": secretenv_core::cli_api::test_support::domain::wire::algorithm::SIGNATURE_ED25519,
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "signer_pub": serde_json::to_value(build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD")).unwrap(),
            "mac": "hmac-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
        }
    });

    let result = validator.validate_file_enc_document(&valid_file_enc_doc);
    assert!(
        result.is_ok(),
        "Schema should allow member_handle without '@' in wrap.rh: {:?}",
        result
    );
}
