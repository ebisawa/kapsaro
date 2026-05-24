// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use secretenv_core::cli_api::test_support::domain::common::WrapItem;
use secretenv_core::cli_api::test_support::domain::kv_enc::header::{KvFileAlgorithm, KvHeader};
use secretenv_core::cli_api::test_support::domain::wire::algorithm;
use secretenv_core::cli_api::test_support::helpers::limits::MAX_JSON_DEPTH;
use secretenv_core::cli_api::test_support::wire::token::TokenCodec;
use uuid::Uuid;

fn deeply_nested_json(depth: usize) -> String {
    let mut json = String::new();
    for _ in 0..depth {
        json.push_str(r#"{"nested":"#);
    }
    json.push_str(r#""value""#);
    for _ in 0..depth {
        json.push('}');
    }
    json
}

#[test]
fn file_enc_detect_rejects_non_json() {
    let result = FileEncContent::detect("not json".to_string());
    assert!(result.is_err());
}

#[test]
fn kv_enc_detect_rejects_json() {
    let result = KvEncContent::detect(r#"{"format":"secretenv:format:file-enc@7"}"#.to_string());
    assert!(result.is_err());
}

#[test]
fn encrypted_content_detect_rejects_unknown() {
    let result = EncContent::detect("random text".to_string());
    assert!(result.is_err());
}

#[test]
fn encrypted_content_detect_rejects_json_exceeding_depth_limit() {
    let result = EncContent::detect(deeply_nested_json(MAX_JSON_DEPTH + 1));
    assert!(result.is_err());
    let err = match result {
        Ok(_) => panic!("expected depth-limit error"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("nesting depth exceeds limit"));
}

#[test]
fn new_unchecked_preserves_content() {
    let content = "test content";
    let file = FileEncContent::new_unchecked(content.to_string());
    assert_eq!(file.as_str(), content);

    let kv = KvEncContent::new_unchecked(content.to_string());
    assert_eq!(kv.as_str(), content);
}

#[test]
fn file_enc_schema_error_includes_source_name() {
    let content = r#"{"protected":{"format":"secretenv:format:file-enc@7"}}"#;
    let file = FileEncContent::new_unchecked_with_source(
        content.to_string(),
        ".secretenv/secrets/app.json",
    );

    let error = file.parse().unwrap_err();
    let message = error.format_user_message();

    assert!(message.contains("Invalid secretenv document"));
    assert!(message.contains("Source: .secretenv/secrets/app.json"));
    assert!(message.contains("Reason"));
}

#[test]
fn kv_enc_schema_error_includes_source_name_and_token_context() {
    let head = KvHeader {
        sid: Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").unwrap(),
        alg: KvFileAlgorithm {
            aead: algorithm::AEAD_XCHACHA20_POLY1305.to_string(),
        },
        created_at: "2026-01-14T00:00:00Z".to_string(),
        updated_at: "2026-01-14T00:00:00Z".to_string(),
    };
    let head_token = TokenCodec::encode(TokenCodec::JsonJcs, &head).unwrap();
    let wrap_token = TokenCodec::encode(
        TokenCodec::JsonJcs,
        &serde_json::json!({
            "wrap": [WrapItem {
                recipient_handle: "alice@example.com".to_string(),
                kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
                alg: algorithm::HPKE_X25519_HKDF_SHA256_CHACHA20_POLY1305.to_string(),
                enc: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                ct: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            }]
        }),
    )
    .unwrap();
    let signature_token = TokenCodec::encode(
        TokenCodec::JsonJcs,
        &serde_json::json!({
            "alg": algorithm::SIGNATURE_ED25519,
            "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
            "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
        }),
    )
    .unwrap();
    let content = format!(
        ":SECRETENV_KV 9\n:HEAD {head_token}\n:WRAP {wrap_token}\n:SIG {signature_token}\n"
    );
    let kv = KvEncContent::new_unchecked_with_source(content, ".secretenv/secrets/default.kvenc");

    let error = kv.parse().unwrap_err();
    let message = error.format_user_message();

    assert!(message.contains("Invalid secretenv document"));
    assert!(message.contains("Source: .secretenv/secrets/default.kvenc (SIG token)"));
    assert!(message.contains("signer_pub"));
}
