// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::keygen_helpers::build_dummy_public_key;
use secretenv::format::schema::document::{
    parse_file_enc_str, parse_kv_entry_token, parse_kv_head_token, parse_kv_signature_token,
    parse_kv_wrap_token, parse_public_key_str,
};
use secretenv::format::token::TokenCodec;
use secretenv::model::common::WrapItem;
use secretenv::model::kv_enc::entry::KvEntryValue;
use secretenv::model::kv_enc::header::{KvFileAlgorithm, KvHeader, KvWrap};
use secretenv::model::signature::ArtifactSignature;
use secretenv::model::wire::{algorithm, format};
use secretenv::support::codec::base64_public::encode_base64url_nopad;
use secretenv::support::limits::MAX_WRAP_ITEMS;
use uuid::Uuid;

#[test]
fn test_parse_public_key_str_with_schema() {
    let public_key = serde_json::json!({
        "protected": {
            "format": format::PUBLIC_KEY_V6,
            "subject_handle": "alice@example.com",
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
        "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    });

    let parsed = parse_public_key_str(&public_key.to_string(), "inline public key").unwrap();
    assert_eq!(parsed.protected.subject_handle, "alice@example.com");
}

#[test]
fn test_parse_file_enc_str_with_schema() {
    let sid = "123e4567-e89b-12d3-a456-426614174000";
    let file_enc = serde_json::json!({
        "protected": {
            "format": format::FILE_ENC_V5,
            "sid": sid,
            "payload": {
                "protected": {
                    "format": format::FILE_PAYLOAD_V5,
                    "sid": sid,
                    "alg": { "aead": algorithm::AEAD_XCHACHA20_POLY1305 }
                },
                "encrypted": {
                    "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "ct": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                }
            },
            "wrap": [{
                "rh": "alice@example.com",
                "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
                "alg": algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305,
                "enc": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "ct": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }],
            "created_at": "2026-01-14T00:00:00Z",
            "updated_at": "2026-01-14T00:00:00Z"
        },
        "signature": {
            "alg": algorithm::SIGNATURE_ED25519,
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "signer_pub": build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
            "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
        }
    });

    let parsed = parse_file_enc_str(&file_enc.to_string(), "inline file-enc").unwrap();
    assert_eq!(parsed.protected.format, format::FILE_ENC_V5);
}

#[test]
fn test_parse_file_enc_str_rejects_non_canonical_signature_base64url() {
    let sid = "123e4567-e89b-12d3-a456-426614174000";
    let mut non_canonical_sig = encode_base64url_nopad(&[0u8; 64]);
    non_canonical_sig.replace_range(85..86, "B");
    let file_enc = serde_json::json!({
        "protected": {
            "format": format::FILE_ENC_V5,
            "sid": sid,
            "payload": {
                "protected": {
                    "format": format::FILE_PAYLOAD_V5,
                    "sid": sid,
                    "alg": { "aead": algorithm::AEAD_XCHACHA20_POLY1305 }
                },
                "encrypted": {
                    "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "ct": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                }
            },
            "wrap": [{
                "rh": "alice@example.com",
                "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
                "alg": algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305,
                "enc": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "ct": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }],
            "created_at": "2026-01-14T00:00:00Z",
            "updated_at": "2026-01-14T00:00:00Z"
        },
        "signature": {
            "alg": algorithm::SIGNATURE_ED25519,
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "signer_pub": build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
            "sig": non_canonical_sig
        }
    });

    let result = parse_file_enc_str(&file_enc.to_string(), "inline file-enc");

    assert!(result.is_err());
    let error = result.unwrap_err();
    let message = error.format_user_message();
    assert!(message.contains("Invalid secretenv document"));
    assert!(message.contains("signature.sig"));
}

#[test]
fn test_parse_kv_tokens_with_schema() {
    let kv_salt = encode_base64url_nopad(&[0u8; 32]);
    let head = KvHeader {
        sid: Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap(),
        alg: KvFileAlgorithm {
            aead: algorithm::AEAD_XCHACHA20_POLY1305.to_string(),
        },
        created_at: "2026-01-14T00:00:00Z".to_string(),
        updated_at: "2026-01-14T00:00:00Z".to_string(),
    };
    let wrap = KvWrap {
        wrap: vec![WrapItem {
            recipient_handle: "alice@example.com".to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
            alg: algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305.to_string(),
            enc: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            ct: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        }],
        removed_recipients: None,
    };
    let entry = KvEntryValue {
        salt: kv_salt,
        nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        ct: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        disclosed: false,
    };
    let signature = ArtifactSignature {
        alg: algorithm::SIGNATURE_ED25519.to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        signer_pub: build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
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
fn test_parse_kv_head_token_requires_aead_algorithm() {
    let head = serde_json::json!({
        "sid": "123e4567-e89b-12d3-a456-426614174000",
        "created_at": "2026-01-14T00:00:00Z",
        "updated_at": "2026-01-14T00:00:00Z"
    });
    let head_token = TokenCodec::encode(TokenCodec::JsonJcs, &head).unwrap();

    let err = parse_kv_head_token(&head_token).unwrap_err();

    assert!(err.to_string().contains("Invalid secretenv document"));
}

#[test]
fn test_parse_kv_head_token_rejects_unsupported_aead_algorithm() {
    let head = serde_json::json!({
        "sid": "123e4567-e89b-12d3-a456-426614174000",
        "alg": { "aead": "aes-256-gcm" },
        "created_at": "2026-01-14T00:00:00Z",
        "updated_at": "2026-01-14T00:00:00Z"
    });
    let head_token = TokenCodec::encode(TokenCodec::JsonJcs, &head).unwrap();

    let err = parse_kv_head_token(&head_token).unwrap_err();

    assert!(err.to_string().contains("Invalid secretenv document"));
}

#[test]
fn test_parse_kv_signature_token_rejects_unknown_field_error() {
    let invalid_token = TokenCodec::encode(
        TokenCodec::JsonJcs,
        &serde_json::json!({
            "alg": algorithm::SIGNATURE_ED25519,
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ",
            "unexpected": true
        }),
    )
    .unwrap();

    let result = parse_kv_signature_token(&invalid_token);
    let error = result.unwrap_err();
    let message = error.format_user_message();
    assert!(message.contains("Invalid secretenv document"));
    assert!(message.contains("document"));
    assert!(message.contains("unexpected"));
    assert!(!message.contains("E_SCHEMA_INVALID"));
    assert!(!message.contains("schema"));
}

#[test]
fn test_parse_kv_signature_token_requires_signer_pub_error() {
    let invalid_token = TokenCodec::encode(
        TokenCodec::JsonJcs,
        &serde_json::json!({
            "alg": algorithm::SIGNATURE_ED25519,
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
        }),
    )
    .unwrap();

    let result = parse_kv_signature_token(&invalid_token);
    let error = result.unwrap_err();
    let message = error.format_user_message();
    assert!(message.contains("Invalid secretenv document"));
    assert!(message.contains("signer_pub"));
    assert!(!message.contains("E_SCHEMA_INVALID"));
    assert!(!message.contains("schema"));
}

#[test]
fn test_parse_file_enc_str_rejects_wrap_count_over_limit() {
    let sid = "123e4567-e89b-12d3-a456-426614174000";
    let wrap_item = serde_json::json!({
        "rh": "alice@example.com",
        "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
        "alg": algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305,
        "enc": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "ct": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    });
    let wrap: Vec<_> = (0..=MAX_WRAP_ITEMS).map(|_| wrap_item.clone()).collect();
    let file_enc = serde_json::json!({
        "protected": {
            "format": format::FILE_ENC_V5,
            "sid": sid,
            "payload": {
                "protected": {
                    "format": format::FILE_PAYLOAD_V5,
                    "sid": sid,
                    "alg": { "aead": algorithm::AEAD_XCHACHA20_POLY1305 }
                },
                "encrypted": {
                    "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "ct": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                }
            },
            "wrap": wrap,
            "created_at": "2026-01-14T00:00:00Z",
            "updated_at": "2026-01-14T00:00:00Z"
        },
        "signature": {
            "alg": algorithm::SIGNATURE_ED25519,
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "signer_pub": build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
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
        recipient_handle: "alice@example.com".to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        alg: algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305.to_string(),
        enc: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        ct: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
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

#[test]
fn test_parse_file_enc_str_rejects_duplicate_wrap_rh() {
    let sid = "123e4567-e89b-12d3-a456-426614174000";
    let file_enc = serde_json::json!({
        "protected": {
            "format": format::FILE_ENC_V5,
            "sid": sid,
            "payload": {
                "protected": {
                    "format": format::FILE_PAYLOAD_V5,
                    "sid": sid,
                    "alg": { "aead": algorithm::AEAD_XCHACHA20_POLY1305 }
                },
                "encrypted": {
                    "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "ct": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                }
            },
            "wrap": [
                {
                    "rh": "alice@example.com",
                    "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
                    "alg": algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305,
                    "enc": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "ct": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                },
                {
                    "rh": "alice@example.com",
                    "kid": "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D",
                    "alg": algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305,
                    "enc": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "ct": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                }
            ],
            "created_at": "2026-01-14T00:00:00Z",
            "updated_at": "2026-01-14T00:00:00Z"
        },
        "signature": {
            "alg": algorithm::SIGNATURE_ED25519,
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "signer_pub": build_dummy_public_key("7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"),
            "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
        }
    });

    let result = parse_file_enc_str(&file_enc.to_string(), "inline file-enc");
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("E_DUPLICATE_RECIPIENT_HANDLE"));
}

#[test]
fn test_parse_kv_wrap_token_rejects_duplicate_wrap_rh() {
    let wrap = KvWrap {
        wrap: vec![
            WrapItem {
                recipient_handle: "alice@example.com".to_string(),
                kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
                alg: algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305.to_string(),
                enc: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                ct: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            },
            WrapItem {
                recipient_handle: "alice@example.com".to_string(),
                kid: "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D".to_string(),
                alg: algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305.to_string(),
                enc: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                ct: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            },
        ],
        removed_recipients: None,
    };
    let wrap_token = TokenCodec::encode(TokenCodec::JsonJcs, &wrap).unwrap();

    let result = parse_kv_wrap_token(&wrap_token);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("E_DUPLICATE_RECIPIENT_HANDLE"));
}
