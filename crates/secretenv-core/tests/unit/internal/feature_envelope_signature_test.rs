// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use ed25519_dalek::SigningKey;

use super::*;
use crate::crypto::types::keys::MasterKey;
use crate::feature::envelope::key_possession::build_kv_key_possession_proof;
use crate::feature::envelope::key_schedule::KvKeySchedule;
use crate::format::kv::enc::parser::KvEncParser;
use crate::format::signature::build_artifact_signature_input;
use crate::model::kv_enc::document::KvEncDocument;
use crate::model::kv_enc::header::{KvFileAlgorithm, KvHeader, KvWrap};
use crate::model::public_key::{Attestation, IdentityKeys, JwkOkpPublicKey, PublicKeyProtected};
use crate::model::signature::ArtifactSignature;
use crate::model::wire::algorithm;
use uuid::Uuid;

fn build_dummy_public_key(kid: &str) -> PublicKey {
    PublicKey {
        protected: PublicKeyProtected {
            format: "secretenv:format:public-key@7".to_string(),
            subject_handle: "signer@test".to_string(),
            kid: kid.to_string(),
                            keys: IdentityKeys {
                    kem: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: "X25519".to_string(),
                        x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    },
                    sig: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: "Ed25519".to_string(),
                        x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    },
                },
                attestation: Attestation {
                    method: "ssh-sign".to_string(),
                    pub_: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    sig: "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ".to_string(),
                },
            binding_claims: None,
            expires_at: "2099-01-01T00:00:00Z".to_string(),
            created_at: Some("2026-01-01T00:00:00Z".to_string()),
        },
        signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    }
}

fn build_test_signing_context<'a>(signing_key: &'a SigningKey, kid: &'a str) -> SigningContext<'a> {
    SigningContext {
        signing_key,
        signer_kid: kid,
        signer_pub: build_dummy_public_key(kid),
        debug: false,
    }
}

#[test]
fn test_append_kv_signature_produces_sig_line() {
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let master_key = MasterKey::new([7u8; 32]);
    let sid = Uuid::new_v4();
    let mac_key = KvKeySchedule::extract(&master_key, &sid)
        .unwrap()
        .derive_mac_key()
        .unwrap();
    let kid = "test-kid";
    let unsigned = ":SECRETENV_KV 9\n:HEAD {}\n:WRAP {}\nKEY token\n";
    let signing = build_test_signing_context(&signing_key, kid);

    let result = append_kv_signature(unsigned, &mac_key, &signing, TokenCodec::JsonJcs, "test");

    assert!(result.is_ok());
    let signed = result.unwrap();
    assert!(signed.starts_with(unsigned));
    assert!(signed.contains(":SIG "));
    assert!(signed.ends_with('\n'));
}

#[test]
fn test_append_kv_signature_preserves_unsigned_content() {
    let signing_key = SigningKey::from_bytes(&[13u8; 32]);
    let master_key = MasterKey::new([7u8; 32]);
    let sid = Uuid::new_v4();
    let mac_key = KvKeySchedule::extract(&master_key, &sid)
        .unwrap()
        .derive_mac_key()
        .unwrap();
    let unsigned = ":SECRETENV_KV 9\n:HEAD tok\n:WRAP tok\nA val\nB val\n";
    let signing = build_test_signing_context(&signing_key, "kid");

    let signed =
        append_kv_signature(unsigned, &mac_key, &signing, TokenCodec::JsonJcs, "test").unwrap();

    assert!(signed.starts_with(unsigned));
    let extra = &signed[unsigned.len()..];
    assert!(extra.starts_with(":SIG "));
    assert_eq!(extra.matches('\n').count(), 1);
}

#[test]
fn test_verify_kv_signature_rejects_tampered_signature_kid() {
    let signing_key = SigningKey::from_bytes(&[17u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let master_key = MasterKey::new([7u8; 32]);
    let sid = Uuid::new_v4();
    let mac_key = KvKeySchedule::extract(&master_key, &sid)
        .unwrap()
        .derive_mac_key()
        .unwrap();
    let unsigned = ":SECRETENV_KV 9\n:HEAD {}\n:WRAP {}\nKEY token\n";
    let signing = build_test_signing_context(&signing_key, "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD");
    let mac = build_kv_key_possession_proof(unsigned, &mac_key, signing.signer_kid, false).unwrap();
    let sig_input = build_artifact_signature_input(
        algorithm::SIGNATURE_ED25519,
        signing.signer_kid,
        unsigned.as_bytes(),
        mac.as_str(),
    )
    .unwrap();
    let mut signature = build_artifact_signature(
        &sig_input,
        &signing_key,
        signing.signer_kid,
        signing.signer_pub.clone(),
        mac,
    )
    .unwrap();
    let document = build_test_kv_document(unsigned, sid, signature.clone());

    verify_kv_signature(&document, &verifying_key, &signature, false).unwrap();

    signature.kid = "4Z8N6K1W3Q7RT5YH9M2PC4XV8D1B6FJA".to_string();
    let result = verify_kv_signature(&document, &verifying_key, &signature, false);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Signature verification failed"));
}

fn build_test_kv_document(
    unsigned: &str,
    sid: Uuid,
    signature: ArtifactSignature,
) -> KvEncDocument {
    KvEncDocument::new(
        unsigned.to_string(),
        KvEncParser::new(unsigned).parse_all().unwrap(),
        KvHeader {
            sid,
            alg: KvFileAlgorithm {
                aead: algorithm::AEAD_XCHACHA20_POLY1305.to_string(),
            },
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        },
        KvWrap {
            wrap: Vec::new(),
            removed_recipients: None,
        },
        Vec::new(),
        String::new(),
        signature,
    )
}
