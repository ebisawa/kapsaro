// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::test_utils::ALICE_MEMBER_HANDLE;
use secretenv::feature::envelope::binding;
use secretenv::feature::key::protection::binding as private_key_binding;
use secretenv::model::wire::{algorithm, context as wire_context, format};
use uuid::Uuid;

/// Test HPKE info for kv-file (WRAP line) - v3 format
#[test]
fn test_hpke_info_kv_file() {
    let sid = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
    let kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

    let info = binding::build_kv_wrap_info(&sid, kid).unwrap();

    // Should be valid UTF-8 JSON
    let info_str = std::str::from_utf8(info.as_bytes()).unwrap();

    // Should parse as JSON
    let parsed: serde_json::Value = serde_json::from_str(info_str).unwrap();

    // Should have required fields
    assert_eq!(parsed["p"], wire_context::HPKE_INFO_KV_WRAP_V6);
    assert_eq!(parsed["sid"], sid.to_string());
    assert_eq!(parsed["kid"], kid);
    // Should NOT have "rd" field (removed in Rev29)
    assert!(parsed.get("rd").is_none());
}

/// Test HPKE info for file-enc - v3 format (Rev29: removed rd field)
#[test]
fn test_hpke_info_file() {
    let sid = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
    let kid = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE";

    let info = binding::build_file_wrap_info(&sid, kid).unwrap();

    // Should be valid UTF-8 JSON
    let info_str = std::str::from_utf8(info.as_bytes()).unwrap();

    // Should parse as JSON
    let parsed: serde_json::Value = serde_json::from_str(info_str).unwrap();

    // Should have required fields
    assert_eq!(parsed["p"], wire_context::HPKE_INFO_FILE_WRAP_V5);
    assert_eq!(parsed["sid"], sid.to_string());
    assert_eq!(parsed["kid"], kid);
    // Should NOT have "rd" field (removed in Rev29)
    assert!(parsed.get("rd").is_none());

    // Should NOT have "name", "n", or "secret_id" fields (Rev9: name removed)
    assert!(parsed.get("name").is_none());
    assert!(parsed.get("n").is_none());
    assert!(parsed.get("secret_id").is_none());
}

/// Test payload AAD for kv-enc - v3 format
#[test]
fn test_aad_payload_kv() {
    let sid = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
    let key = "MY_KEY";

    let aad = binding::build_kv_entry_aad(&sid, key).unwrap();

    // Should be valid UTF-8 JSON
    let aad_str = std::str::from_utf8(aad.as_bytes()).unwrap();

    // Should parse as JSON
    let parsed: serde_json::Value = serde_json::from_str(aad_str).unwrap();

    // Should have required fields
    assert_eq!(parsed["p"], wire_context::AAD_KV_ENTRY_PAYLOAD_V6);
    assert_eq!(parsed["sid"], sid.to_string());
    assert_eq!(parsed["k"], key);
    // salt is NOT in AAD (used in HKDF salt parameter instead)
    assert!(parsed.get("salt").is_none());
    assert!(parsed.get("rd").is_none()); // recipients NOT in AAD
}

/// Test payload AAD for file-enc - v3 format (envelope: JCS of payload.protected)
#[test]
fn test_aad_file_payload() {
    use secretenv::model::file_enc::{FileEncAlgorithm, FilePayloadHeader};

    let sid = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
    let payload_protected = FilePayloadHeader {
        format: format::FILE_PAYLOAD_V5.to_string(),
        sid,
        alg: FileEncAlgorithm {
            aead: algorithm::AEAD_XCHACHA20_POLY1305.to_string(),
        },
    };

    let aad = binding::build_file_payload_aad(&payload_protected).unwrap();

    // Should be valid UTF-8 JSON
    let aad_str = std::str::from_utf8(aad.as_bytes()).unwrap();

    // Should parse as JSON
    let parsed: serde_json::Value = serde_json::from_str(aad_str).unwrap();

    // Should have required fields from payload.protected
    assert_eq!(parsed["format"], format::FILE_PAYLOAD_V5);
    assert_eq!(parsed["sid"], sid.to_string());
    assert_eq!(parsed["alg"]["aead"], algorithm::AEAD_XCHACHA20_POLY1305);
}

/// Test AAD for PrivateKey encryption - v3 format (envelope: JCS of protected)
#[test]
fn test_aad_private_key() {
    use secretenv::model::private_key::{PrivateKeyAlgorithm, PrivateKeyProtected};

    let protected = PrivateKeyProtected {
        format: format::PRIVATE_KEY_V7.to_string(),
        subject_handle: ALICE_MEMBER_HANDLE.to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        alg: PrivateKeyAlgorithm::SshSig {
            fpr: "SHA256:ABCDEFGH123456789".to_string(),
            ikm_salt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            hkdf_salt: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
            aead: algorithm::AEAD_XCHACHA20_POLY1305.to_string(),
        },
        created_at: "2025-01-01T00:00:00Z".to_string(),
        expires_at: "2027-01-15T00:00:00Z".to_string(),
    };

    let aad = private_key_binding::build_private_key_aad(&protected).unwrap();

    // Should be valid UTF-8 JSON
    let aad_str = std::str::from_utf8(aad.as_bytes()).unwrap();

    // Should parse as JSON
    let parsed: serde_json::Value = serde_json::from_str(aad_str).unwrap();

    // Should have required fields from protected
    assert_eq!(parsed["format"], format::PRIVATE_KEY_V7);
    assert_eq!(parsed["subject_handle"], ALICE_MEMBER_HANDLE);
    assert_eq!(parsed["kid"], "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD");
    assert_eq!(parsed["alg"]["fpr"], "SHA256:ABCDEFGH123456789");
    assert_eq!(parsed["expires_at"], "2027-01-15T00:00:00Z");
}
