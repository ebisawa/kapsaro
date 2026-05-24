// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/encrypt/kv entry operations (set/unset) via KvDocumentBuilder

use ed25519_dalek::SigningKey;
use secretenv_core::cli_api::test_support::domain::kv_enc::document::KvEncDocument;
use secretenv_core::cli_api::test_support::domain::kv_enc::header::KvHeader;
use secretenv_core::cli_api::test_support::domain::public_key::VerifiedRecipientKey;
use secretenv_core::cli_api::test_support::operations::context::crypto::SigningContext;
use secretenv_core::cli_api::test_support::operations::key::material::generate_keypairs;
use secretenv_core::cli_api::test_support::operations::kv::builder::KvDocumentBuilder;
use secretenv_core::cli_api::test_support::operations::kv::encrypt::encrypt_kv_document;
use secretenv_core::cli_api::test_support::primitives::types::keys::MasterKey;
use secretenv_core::cli_api::test_support::wire::kv::document::parse_kv_document;
use secretenv_core::cli_api::test_support::wire::token::TokenCodec;
use std::collections::HashMap;

fn generate_signing_ctx_for_test() -> (SigningKey, String) {
    (
        SigningKey::from_bytes(&[7u8; 32]),
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
    )
}

fn build_dummy_signer_pub(
    signing_key: &SigningKey,
    kid: &str,
) -> secretenv_core::cli_api::test_support::domain::public_key::PublicKey {
    use secretenv_core::cli_api::test_support::domain::public_key::{
        Attestation, IdentityKeys, JwkOkpPublicKey, PublicKey, PublicKeyProtected,
    };
    use secretenv_core::cli_api::test_support::helpers::codec::base64_public::encode_base64url_nopad;

    let vk = signing_key.verifying_key();
    let b64url = |b: &[u8]| encode_base64url_nopad(b);
    let keypairs = generate_keypairs().unwrap();
    let kem_pk = &keypairs.kem_pk;

    PublicKey {
        protected: PublicKeyProtected {
            format: "secretenv:format:public-key@7".to_string(),
            subject_handle: "test@example.com".to_string(),
            kid: kid.to_string(),
            keys: IdentityKeys {
                kem: JwkOkpPublicKey {
                    kty: "OKP".to_string(),
                    crv: "X25519".to_string(),
                    x: b64url(kem_pk.as_bytes()),
                },
                sig: JwkOkpPublicKey {
                    kty: "OKP".to_string(),
                    crv: "Ed25519".to_string(),
                    x: b64url(vk.as_bytes()),
                },
            },
            binding_claims: None,
            attestation: Attestation {
                method: "ssh-sign".to_string(),
                pub_: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE".to_string(),
                sig: b64url(&[0u8; 64]),
            },
            expires_at: "2099-01-01T00:00:00Z".to_string(),
            created_at: Some("2026-01-01T00:00:00Z".to_string()),
        },
        signature: b64url(&[0u8; 64]),
    }
}

fn build_verified_recipient_key_for_test(
    signing_key: &SigningKey,
    kid: &str,
) -> VerifiedRecipientKey {
    use ed25519_dalek::Signer;
    use secretenv_core::cli_api::test_support::domain::public_key::{
        Attestation, AttestationProof, AttestedKeyStatement, IdentityKeys, JwkOkpPublicKey,
        PublicKey, PublicKeyProtected, VerifiedPublicKeyAttested,
    };
    use secretenv_core::cli_api::test_support::domain::verification::{
        ExpiryProof, SelfSignatureProof,
    };
    use secretenv_core::cli_api::test_support::helpers::codec::base64_public::encode_base64url_nopad;

    let b64url = |b: &[u8]| encode_base64url_nopad(b);
    let keypairs = generate_keypairs().unwrap();
    let kem_pk = &keypairs.kem_pk;
    let vk = signing_key.verifying_key();

    let test_pk = PublicKey {
        protected: PublicKeyProtected {
            format: "secretenv:format:public-key@7".to_string(),
            subject_handle: "test@example.com".to_string(),
            kid: kid.to_string(),
            keys: IdentityKeys {
                kem: JwkOkpPublicKey {
                    kty: "OKP".to_string(),
                    crv: "X25519".to_string(),
                    x: b64url(kem_pk.as_bytes()),
                },
                sig: JwkOkpPublicKey {
                    kty: "OKP".to_string(),
                    crv: "Ed25519".to_string(),
                    x: b64url(vk.as_bytes()),
                },
            },
            binding_claims: None,
            attestation: Attestation {
                method: "test".to_string(),
                pub_: "test".to_string(),
                sig: b64url(b"test"),
            },
            expires_at: "2099-01-01T00:00:00Z".to_string(),
            created_at: Some("2026-01-01T00:00:00Z".to_string()),
        },
        signature: b64url(signing_key.sign(b"test").to_bytes().as_ref()),
    };

    let proof = AttestationProof {
        method: "test".to_string(),
        ssh_pub: "test".to_string(),
        verified_at: None,
    };
    let attested = AttestedKeyStatement::new(test_pk.protected.keys.clone(), proof);
    let self_sig_proof = SelfSignatureProof::new();
    let attested_key = VerifiedPublicKeyAttested::new(test_pk, self_sig_proof, attested);
    VerifiedRecipientKey::new(attested_key, ExpiryProof::new())
}

fn encrypt_kv_document_for_test(
    entries: &[(&str, &str)],
    signing_key: &SigningKey,
    kid: &str,
) -> String {
    let verified_member = build_verified_recipient_key_for_test(signing_key, kid);

    let mut kv_map = HashMap::new();
    for (k, v) in entries {
        kv_map.insert(k.to_string(), v.to_string());
    }

    let signing = SigningContext {
        signing_key,
        signer_kid: kid,
        signer_pub: build_dummy_signer_pub(signing_key, kid),
        debug: false,
    };

    encrypt_kv_document(&kv_map, &[verified_member], &signing, TokenCodec::JsonJcs).unwrap()
}

/// Build a test context for set/unset tests: (initial_content, doc, signing_key, kid)
fn setup_test_ctx(entries: &[(&str, &str)]) -> (String, KvEncDocument, SigningKey, String) {
    let (signing_key, kid) = generate_signing_ctx_for_test();
    let initial = encrypt_kv_document_for_test(entries, &signing_key, &kid);
    let doc = parse_kv_document(&initial).unwrap();
    (initial, doc, signing_key, kid)
}

fn wrap_token_from(content: &str) -> String {
    content
        .lines()
        .find(|l: &&str| l.starts_with(":WRAP "))
        .unwrap()
        .strip_prefix(":WRAP ")
        .unwrap()
        .to_string()
}

fn kv_token_from(content: &str, key: &str) -> Option<String> {
    content.lines().find_map(|l: &str| {
        let prefix = format!("{} ", key);
        l.strip_prefix(&prefix).map(|t| t.to_string())
    })
}

/// Helper: build a signed document with set_entries via KvDocumentBuilder
fn builder_set_entries(
    updated_head: &KvHeader,
    doc: &KvEncDocument,
    new_entries: &HashMap<&str, &str>,
    signing: &SigningContext<'_>,
) -> String {
    let mut unsigned = KvDocumentBuilder::from_lines(
        updated_head.clone(),
        None,
        &doc.lines,
        TokenCodec::JsonJcs,
        signing.debug,
    )
    .unwrap()
    .build();
    unsigned.set_entries(new_entries);
    unsigned.sign(&MasterKey::new([3u8; 32]), signing).unwrap()
}

/// Helper: build a signed document with set_entries for a single entry
fn builder_set_entry(
    updated_head: &KvHeader,
    doc: &KvEncDocument,
    target_key: &str,
    new_entry_token: &str,
    signing: &SigningContext<'_>,
) -> String {
    let entries = HashMap::from([(target_key, new_entry_token)]);
    builder_set_entries(updated_head, doc, &entries, signing)
}

/// Helper: build a signed document with unset_entry via KvDocumentBuilder
fn builder_unset_entry(
    updated_head: &KvHeader,
    doc: &KvEncDocument,
    target_key: &str,
    signing: &SigningContext<'_>,
) -> String {
    let mut unsigned = KvDocumentBuilder::from_lines(
        updated_head.clone(),
        None,
        &doc.lines,
        TokenCodec::JsonJcs,
        signing.debug,
    )
    .unwrap()
    .build();
    unsigned.unset_entry(target_key);
    unsigned.sign(&MasterKey::new([3u8; 32]), signing).unwrap()
}

// --- set_entry テスト ---

#[test]
fn test_build_kv_set_entry_adds_new_key() {
    let (initial, doc, signing_key, kid) = setup_test_ctx(&[("KEY1", "val1")]);
    let signing = SigningContext {
        signing_key: &signing_key,
        signer_kid: &kid,
        signer_pub: build_dummy_signer_pub(&signing_key, &kid),
        debug: false,
    };
    let updated_head = KvHeader {
        sid: doc.head.sid,
        alg: doc.head.alg.clone(),
        created_at: doc.head.created_at.clone(),
        updated_at: "2026-01-02T00:00:00Z".to_string(),
    };

    let result = builder_set_entry(&updated_head, &doc, "KEY2", "dummytoken123", &signing);

    assert!(result.contains("KEY2 "), "KEY2 should be present");
    let key1_before = kv_token_from(&initial, "KEY1").unwrap();
    let key1_after = kv_token_from(&result, "KEY1").unwrap();
    assert_eq!(key1_before, key1_after, "KEY1 token should be unchanged");
}

#[test]
fn test_build_kv_set_entry_replaces_existing_key() {
    let (initial, doc, signing_key, kid) = setup_test_ctx(&[("KEY1", "val1"), ("KEY2", "val2")]);
    let signing = SigningContext {
        signing_key: &signing_key,
        signer_kid: &kid,
        signer_pub: build_dummy_signer_pub(&signing_key, &kid),
        debug: false,
    };
    let new_token = "newtoken456";
    let updated_head = KvHeader {
        sid: doc.head.sid,
        alg: doc.head.alg.clone(),
        created_at: doc.head.created_at.clone(),
        updated_at: "2026-01-02T00:00:00Z".to_string(),
    };

    let result = builder_set_entry(&updated_head, &doc, "KEY1", new_token, &signing);

    let key1_after = kv_token_from(&result, "KEY1").unwrap();
    assert_eq!(key1_after, new_token, "KEY1 should have new token");
    let key2_before = kv_token_from(&initial, "KEY2").unwrap();
    let key2_after = kv_token_from(&result, "KEY2").unwrap();
    assert_eq!(key2_before, key2_after, "KEY2 token should be unchanged");
}

#[test]
fn test_build_kv_set_entry_preserves_wrap_token() {
    let (initial, doc, signing_key, kid) = setup_test_ctx(&[("KEY1", "val1")]);
    let signing = SigningContext {
        signing_key: &signing_key,
        signer_kid: &kid,
        signer_pub: build_dummy_signer_pub(&signing_key, &kid),
        debug: false,
    };
    let updated_head = KvHeader {
        sid: doc.head.sid,
        alg: doc.head.alg.clone(),
        created_at: doc.head.created_at.clone(),
        updated_at: "2026-01-02T00:00:00Z".to_string(),
    };

    let result = builder_set_entry(&updated_head, &doc, "NEW_KEY", "sometoken", &signing);

    let wrap_before = wrap_token_from(&initial);
    let wrap_after = wrap_token_from(&result);
    assert_eq!(wrap_before, wrap_after, "WRAP token should be unchanged");
}

// --- unset_entry テスト ---

#[test]
fn test_build_kv_unset_entry_removes_target_key() {
    let (initial, doc, signing_key, kid) = setup_test_ctx(&[("KEY1", "val1"), ("KEY2", "val2")]);
    let signing = SigningContext {
        signing_key: &signing_key,
        signer_kid: &kid,
        signer_pub: build_dummy_signer_pub(&signing_key, &kid),
        debug: false,
    };
    let updated_head = KvHeader {
        sid: doc.head.sid,
        alg: doc.head.alg.clone(),
        created_at: doc.head.created_at.clone(),
        updated_at: "2026-01-02T00:00:00Z".to_string(),
    };

    let result = builder_unset_entry(&updated_head, &doc, "KEY1", &signing);

    assert!(!result.contains("KEY1 "), "KEY1 should be removed");
    let key2_before = kv_token_from(&initial, "KEY2").unwrap();
    let key2_after = kv_token_from(&result, "KEY2").unwrap();
    assert_eq!(key2_before, key2_after, "KEY2 token should be unchanged");
}

#[test]
fn test_build_kv_unset_entry_preserves_wrap_token() {
    let (initial, doc, signing_key, kid) = setup_test_ctx(&[("KEY1", "val1"), ("KEY2", "val2")]);
    let signing = SigningContext {
        signing_key: &signing_key,
        signer_kid: &kid,
        signer_pub: build_dummy_signer_pub(&signing_key, &kid),
        debug: false,
    };
    let updated_head = KvHeader {
        sid: doc.head.sid,
        alg: doc.head.alg.clone(),
        created_at: doc.head.created_at.clone(),
        updated_at: "2026-01-02T00:00:00Z".to_string(),
    };

    let result = builder_unset_entry(&updated_head, &doc, "KEY1", &signing);

    let wrap_before = wrap_token_from(&initial);
    let wrap_after = wrap_token_from(&result);
    assert_eq!(wrap_before, wrap_after, "WRAP token should be unchanged");
}

#[test]
fn test_build_kv_unset_entry_last_entry() {
    let (_initial, doc, signing_key, kid) = setup_test_ctx(&[("ONLY_KEY", "val")]);
    let signing = SigningContext {
        signing_key: &signing_key,
        signer_kid: &kid,
        signer_pub: build_dummy_signer_pub(&signing_key, &kid),
        debug: false,
    };
    let updated_head = KvHeader {
        sid: doc.head.sid,
        alg: doc.head.alg.clone(),
        created_at: doc.head.created_at.clone(),
        updated_at: "2026-01-02T00:00:00Z".to_string(),
    };

    let result = builder_unset_entry(&updated_head, &doc, "ONLY_KEY", &signing);

    use secretenv_core::cli_api::test_support::wire::kv::enc::parser::KvEncParser;
    let lines = KvEncParser::new(&result).parse_all().unwrap();
    assert!(!result.contains("ONLY_KEY"), "ONLY_KEY should be removed");
    assert!(result.contains(":HEAD "), "HEAD line should exist");
    assert!(result.contains(":SIG "), "SIG line should exist");
    let _ = lines;
}

// --- set_entries テスト ---

#[test]
fn test_build_kv_set_entries_updates_and_adds_multiple_keys() {
    let (initial, doc, signing_key, kid) = setup_test_ctx(&[("KEY1", "val1")]);
    let signing = SigningContext {
        signing_key: &signing_key,
        signer_kid: &kid,
        signer_pub: build_dummy_signer_pub(&signing_key, &kid),
        debug: false,
    };
    let updated_head = KvHeader {
        sid: doc.head.sid,
        alg: doc.head.alg.clone(),
        created_at: doc.head.created_at.clone(),
        updated_at: "2026-01-02T00:00:00Z".to_string(),
    };

    let new_key1_token = "updated_token_key1";
    let new_key2_token = "new_token_key2";
    let entries = HashMap::from([("KEY1", new_key1_token), ("KEY2", new_key2_token)]);

    let result = builder_set_entries(&updated_head, &doc, &entries, &signing);

    let key1_before = kv_token_from(&initial, "KEY1").unwrap();
    let key1_after = kv_token_from(&result, "KEY1").unwrap();
    assert_ne!(key1_before, key1_after, "KEY1 should have been updated");
    assert_eq!(key1_after, new_key1_token, "KEY1 should have the new token");

    let key2_after = kv_token_from(&result, "KEY2").unwrap();
    assert_eq!(key2_after, new_key2_token, "KEY2 should be present");

    let key1_count = result
        .lines()
        .filter(|l: &&str| l.starts_with("KEY1 "))
        .count();
    assert_eq!(key1_count, 1, "KEY1 should appear exactly once");

    let wrap_before = wrap_token_from(&initial);
    let wrap_after = wrap_token_from(&result);
    assert_eq!(wrap_before, wrap_after, "WRAP token should be unchanged");
}

#[test]
fn test_build_kv_set_entries_preserves_existing_keys_not_in_map() {
    let (initial, doc, signing_key, kid) =
        setup_test_ctx(&[("KEY1", "val1"), ("KEY2", "val2"), ("KEY3", "val3")]);
    let signing = SigningContext {
        signing_key: &signing_key,
        signer_kid: &kid,
        signer_pub: build_dummy_signer_pub(&signing_key, &kid),
        debug: false,
    };
    let updated_head = KvHeader {
        sid: doc.head.sid,
        alg: doc.head.alg.clone(),
        created_at: doc.head.created_at.clone(),
        updated_at: "2026-01-02T00:00:00Z".to_string(),
    };

    let entries = HashMap::from([("KEY2", "replaced_token")]);

    let result = builder_set_entries(&updated_head, &doc, &entries, &signing);

    let key1_before = kv_token_from(&initial, "KEY1").unwrap();
    let key1_after = kv_token_from(&result, "KEY1").unwrap();
    assert_eq!(key1_before, key1_after, "KEY1 should be unchanged");

    let key3_before = kv_token_from(&initial, "KEY3").unwrap();
    let key3_after = kv_token_from(&result, "KEY3").unwrap();
    assert_eq!(key3_before, key3_after, "KEY3 should be unchanged");

    let key2_after = kv_token_from(&result, "KEY2").unwrap();
    assert_eq!(key2_after, "replaced_token", "KEY2 should have new token");
}

#[test]
fn test_build_kv_set_entries_new_keys_sorted_deterministically() {
    let (_initial, doc, signing_key, kid) = setup_test_ctx(&[("EXISTING", "val")]);
    let signing = SigningContext {
        signing_key: &signing_key,
        signer_kid: &kid,
        signer_pub: build_dummy_signer_pub(&signing_key, &kid),
        debug: false,
    };
    let updated_head = KvHeader {
        sid: doc.head.sid,
        alg: doc.head.alg.clone(),
        created_at: doc.head.created_at.clone(),
        updated_at: "2026-01-02T00:00:00Z".to_string(),
    };

    let entries = HashMap::from([("ZEBRA", "zt"), ("ALPHA", "at"), ("MIDDLE", "mt")]);

    let result = builder_set_entries(&updated_head, &doc, &entries, &signing);

    let kv_keys: Vec<&str> = result
        .lines()
        .filter(|l: &&str| !l.starts_with(':') && !l.starts_with('#') && l.contains(' '))
        .filter_map(|l: &str| l.split(' ').next())
        .collect();

    // EXISTING should come first (from original), then new keys in alphabetical order
    assert_eq!(kv_keys, vec!["EXISTING", "ALPHA", "MIDDLE", "ZEBRA"]);
}
