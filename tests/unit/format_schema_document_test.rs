// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::keygen_helpers::make_dummy_public_key;
use secretenv::format::schema::document::{
    parse_file_enc_str, parse_kv_entry_token, parse_kv_head_token, parse_kv_signature_token,
    parse_kv_wrap_token, parse_private_key_bytes, parse_public_key_str,
};
use secretenv::format::token::TokenCodec;
use secretenv::model::common::WrapItem;
use secretenv::model::identifiers::{alg, format, hpke, private_key};
use secretenv::model::kv_enc::entry::KvEntryValue;
use secretenv::model::kv_enc::header::{KvHeader, KvWrap};
use secretenv::model::signature::ArtifactSignature;
use secretenv::support::limits::MAX_WRAP_ITEMS;
use uuid::Uuid;

#[test]
fn test_parse_public_key_str_with_schema() {
    let public_key = serde_json::json!({
        "protected": {
            "format": format::PUBLIC_KEY_V4,
            "member_id": "alice@example.com",
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "identity": {
                "keys": {
                    "kem": {
                        "kty": "OKP",
                        "crv": "X25519",
                        "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    },
                    "sig": {
                        "kty": "OKP",
                        "crv": "Ed25519",
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

    let parsed = parse_public_key_str(&public_key.to_string(), "inline public key").unwrap();
    assert_eq!(parsed.protected.member_id, "alice@example.com");
}

#[test]
fn test_parse_private_key_bytes_rejects_legacy_argon2_fields_error() {
    let private_key = serde_json::json!({
        "protected": {
            "format": format::PRIVATE_KEY_V4,
            "member_id": "alice@example.com",
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "alg": {
                "kdf": private_key::PROTECTION_METHOD_ARGON2ID_HKDF_SHA256,
                "salt": "AAAAAAAAAAAAAAAAAAAAAA",
                "aead": alg::AEAD_XCHACHA20_POLY1305,
                "m": 47104
            },
            "created_at": "2026-01-14T00:00:00Z",
            "expires_at": "2027-01-14T00:00:00Z"
        },
        "encrypted": {
            "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "ct": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        }
    });

    let result =
        parse_private_key_bytes(private_key.to_string().as_bytes(), "SECRETENV_PRIVATE_KEY");
    assert!(result.is_err());
}

#[test]
fn test_parse_file_enc_str_with_schema() {
    let sid = "123e4567-e89b-12d3-a456-426614174000";
    let file_enc = serde_json::json!({
        "protected": {
            "format": format::FILE_ENC_V3,
            "sid": sid,
            "payload": {
                "protected": {
                    "format": format::FILE_PAYLOAD_V3,
                    "sid": sid,
                    "alg": { "aead": alg::AEAD_XCHACHA20_POLY1305 }
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
            "alg": alg::SIGNATURE_ED25519,
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "signer_pub": make_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
            "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
        }
    });

    let parsed = parse_file_enc_str(&file_enc.to_string(), "inline file-enc").unwrap();
    assert_eq!(parsed.protected.format, format::FILE_ENC_V3);
}

#[test]
fn test_parse_kv_tokens_with_schema() {
    let head = KvHeader {
        sid: Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap(),
        created_at: "2026-01-14T00:00:00Z".to_string(),
        updated_at: "2026-01-14T00:00:00Z".to_string(),
    };
    let wrap = KvWrap {
        wrap: vec![WrapItem {
            rid: "alice@example.com".to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
            alg: hpke::ALG_HPKE_32_1_3.to_string(),
            enc: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            ct: "AAAAAAAAAAAAAAAA".to_string(),
        }],
        removed_recipients: None,
    };
    let entry = KvEntryValue {
        salt: "AAAAAAAAAAAAAAAAAAAAAA".to_string(),
        k: "DATABASE_URL".to_string(),
        aead: alg::AEAD_XCHACHA20_POLY1305.to_string(),
        nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        ct: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        disclosed: false,
    };
    let signature = ArtifactSignature {
        alg: alg::SIGNATURE_ED25519.to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        signer_pub: make_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
        sig:
            "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
                .to_string(),
    };

    let head_token = TokenCodec::encode(TokenCodec::JsonJcs, &head).unwrap();
    let wrap_token = TokenCodec::encode(TokenCodec::JsonJcs, &wrap).unwrap();
    let entry_token = TokenCodec::encode(TokenCodec::JsonJcs, &entry).unwrap();
    let signature_token = TokenCodec::encode(TokenCodec::JsonJcs, &signature).unwrap();

    assert_eq!(parse_kv_head_token(&head_token).unwrap(), head);
    assert_eq!(parse_kv_wrap_token(&wrap_token).unwrap(), wrap);
    assert_eq!(parse_kv_entry_token(&entry_token).unwrap(), entry);
    assert_eq!(
        parse_kv_signature_token(&signature_token).unwrap(),
        signature
    );
}

#[test]
fn test_parse_kv_signature_token_rejects_unknown_field_error() {
    let invalid_token = TokenCodec::encode(
        TokenCodec::JsonJcs,
        &serde_json::json!({
            "alg": alg::SIGNATURE_ED25519,
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ",
            "unexpected": true
        }),
    )
    .unwrap();

    let result = parse_kv_signature_token(&invalid_token);
    assert!(result.is_err());
}

#[test]
fn test_parse_kv_signature_token_requires_signer_pub_error() {
    let invalid_token = TokenCodec::encode(
        TokenCodec::JsonJcs,
        &serde_json::json!({
            "alg": alg::SIGNATURE_ED25519,
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
        }),
    )
    .unwrap();

    let result = parse_kv_signature_token(&invalid_token);
    assert!(result.is_err());
}

#[test]
fn test_parse_file_enc_str_rejects_wrap_count_over_limit() {
    let sid = "123e4567-e89b-12d3-a456-426614174000";
    let wrap_item = serde_json::json!({
        "rid": "alice@example.com",
        "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        "alg": hpke::ALG_HPKE_32_1_3,
        "enc": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "ct": "AAAAAAAAAAAAAAAA"
    });
    let wrap: Vec<_> = (0..=MAX_WRAP_ITEMS).map(|_| wrap_item.clone()).collect();
    let file_enc = serde_json::json!({
        "protected": {
            "format": format::FILE_ENC_V3,
            "sid": sid,
            "payload": {
                "protected": {
                    "format": format::FILE_PAYLOAD_V3,
                    "sid": sid,
                    "alg": { "aead": alg::AEAD_XCHACHA20_POLY1305 }
                },
                "encrypted": {
                    "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "ct": "AAAAAAAAAAAAAAAA"
                }
            },
            "wrap": wrap,
            "created_at": "2026-01-14T00:00:00Z",
            "updated_at": "2026-01-14T00:00:00Z"
        },
        "signature": {
            "alg": alg::SIGNATURE_ED25519,
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "signer_pub": make_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
            "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
        }
    });

    let result = parse_file_enc_str(&file_enc.to_string(), "inline file-enc");
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("wrap count") || err.contains("1000"));
}

#[test]
fn test_parse_kv_wrap_token_rejects_wrap_count_over_limit() {
    let wrap_item = WrapItem {
        rid: "alice@example.com".to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        alg: hpke::ALG_HPKE_32_1_3.to_string(),
        enc: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        ct: "AAAAAAAAAAAAAAAA".to_string(),
    };
    let wrap = KvWrap {
        wrap: vec![wrap_item; MAX_WRAP_ITEMS + 1],
        removed_recipients: None,
    };
    let wrap_token = TokenCodec::encode(TokenCodec::JsonJcs, &wrap).unwrap();

    let result = parse_kv_wrap_token(&wrap_token);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("wrap count") || err.contains("1000"));
}
