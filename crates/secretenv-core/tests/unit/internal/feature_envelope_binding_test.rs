// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Golden tests for envelope context-binding byte construction.
//!
//! These tests pin the exact JCS bytes used as HPKE info, AEAD AAD, and HKDF context.

use super::*;
use crate::model::file_enc::{FileEncAlgorithm, FilePayloadHeader};
use crate::model::wire::{algorithm, format};

const KID: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
const KEY: &str = "DATABASE_URL";
const NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn sid() -> Uuid {
    Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap()
}

fn bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[test]
fn test_build_file_wrap_info_uses_jcs_golden_bytes() {
    let info = build_file_wrap_info(&sid(), KID).unwrap();

    assert_eq!(
        bytes_to_string(info.as_bytes()),
        concat!(
            r#"{"kid":"7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD","#,
            r#""p":"secretenv:context:hpke-info:file-enc:wrap@7","#,
            r#""sid":"00000000-0000-0000-0000-000000000000"}"#
        )
    );
}

#[test]
fn test_build_kv_wrap_info_uses_jcs_golden_bytes() {
    let info = build_kv_wrap_info(&sid(), KID).unwrap();

    assert_eq!(
        bytes_to_string(info.as_bytes()),
        concat!(
            r#"{"kid":"7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD","#,
            r#""p":"secretenv:context:hpke-info:kv-enc:wrap@9","#,
            r#""sid":"00000000-0000-0000-0000-000000000000"}"#
        )
    );
}

#[test]
fn test_build_file_payload_aad_uses_jcs_golden_bytes() {
    let protected = FilePayloadHeader {
        format: format::FILE_PAYLOAD_V7.to_string(),
        sid: sid(),
        alg: FileEncAlgorithm {
            aead: algorithm::AEAD_XCHACHA20_POLY1305.to_string(),
        },
    };
    let aad = build_file_payload_aad(&protected).unwrap();

    assert_eq!(
        bytes_to_string(aad.as_bytes()),
        concat!(
            r#"{"alg":{"aead":"xchacha20-poly1305"},"#,
            r#""format":"secretenv:format:file-enc:payload@7","#,
            r#""sid":"00000000-0000-0000-0000-000000000000"}"#
        )
    );
}

#[test]
fn test_build_kv_entry_aad_uses_jcs_golden_bytes() {
    let aad = build_kv_entry_aad(&sid(), KEY).unwrap();

    assert_eq!(
        bytes_to_string(aad.as_bytes()),
        concat!(
            r#"{"k":"DATABASE_URL","#,
            r#""p":"secretenv:context:aad:kv-enc:entry-payload@9","#,
            r#""sid":"00000000-0000-0000-0000-000000000000"}"#
        )
    );
}

#[test]
fn test_build_file_key_schedule_context_uses_jcs_golden_bytes() {
    assert_eq!(
        bytes_to_string(&build_file_key_schedule_salt(&sid()).unwrap()),
        concat!(
            r#"{"p":"secretenv:context:hkdf-salt:file-enc@7","#,
            r#""sid":"00000000-0000-0000-0000-000000000000"}"#
        )
    );
    assert_eq!(
        bytes_to_string(build_file_content_key_info(&sid()).unwrap().as_bytes()),
        concat!(
            r#"{"p":"secretenv:context:hkdf-info:file-enc:content-key@7","#,
            r#""sid":"00000000-0000-0000-0000-000000000000"}"#
        )
    );
    assert_eq!(
        bytes_to_string(build_file_mac_key_info(&sid()).unwrap().as_bytes()),
        concat!(
            r#"{"p":"secretenv:context:hkdf-info:file-enc:mac-key@7","#,
            r#""sid":"00000000-0000-0000-0000-000000000000"}"#
        )
    );
}

#[test]
fn test_build_kv_key_schedule_context_uses_jcs_golden_bytes() {
    assert_eq!(
        bytes_to_string(&build_kv_key_schedule_salt(&sid()).unwrap()),
        concat!(
            r#"{"p":"secretenv:context:hkdf-salt:kv-enc@9","#,
            r#""sid":"00000000-0000-0000-0000-000000000000"}"#
        )
    );
    assert_eq!(
        bytes_to_string(build_kv_cek_info(&sid(), KEY, NONCE).unwrap().as_bytes()),
        concat!(
            r#"{"k":"DATABASE_URL","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","#,
            r#""p":"secretenv:context:hkdf-info:kv-enc:cek@9","#,
            r#""sid":"00000000-0000-0000-0000-000000000000"}"#
        )
    );
    assert_eq!(
        bytes_to_string(build_kv_mac_key_info(&sid()).unwrap().as_bytes()),
        concat!(
            r#"{"p":"secretenv:context:hkdf-info:kv-enc:mac-key@9","#,
            r#""sid":"00000000-0000-0000-0000-000000000000"}"#
        )
    );
}
