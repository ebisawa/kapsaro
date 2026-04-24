// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use ed25519_dalek::SigningKey;

use super::*;
use crate::model::public_key::{
    Attestation, Identity, IdentityKeys, JwkOkpPublicKey, PublicKeyProtected,
};

fn build_dummy_public_key(kid: &str) -> PublicKey {
    PublicKey {
        protected: PublicKeyProtected {
            format: "secretenv.public.key@4".to_string(),
            member_id: "signer@test".to_string(),
            kid: kid.to_string(),
            identity: Identity {
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
            },
            binding_claims: None,
            expires_at: "2099-01-01T00:00:00Z".to_string(),
            created_at: Some("2026-01-01T00:00:00Z".to_string()),
        },
        signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    }
}

#[test]
fn test_append_kv_signature_produces_sig_line() {
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let kid = "test-kid";
    let unsigned = ":SECRETENV_KV 3\n:HEAD {}\n:WRAP {}\nKEY token\n";

    let result = append_kv_signature(
        unsigned,
        &signing_key,
        kid,
        build_dummy_public_key(kid),
        TokenCodec::JsonJcs,
        false,
        "test",
    );

    assert!(result.is_ok());
    let signed = result.unwrap();
    assert!(signed.starts_with(unsigned));
    assert!(signed.contains(":SIG "));
    assert!(signed.ends_with('\n'));
}

#[test]
fn test_append_kv_signature_preserves_unsigned_content() {
    let signing_key = SigningKey::from_bytes(&[13u8; 32]);
    let unsigned = ":SECRETENV_KV 3\n:HEAD tok\n:WRAP tok\nA val\nB val\n";

    let signed = append_kv_signature(
        unsigned,
        &signing_key,
        "kid",
        build_dummy_public_key("kid"),
        TokenCodec::JsonJcs,
        false,
        "test",
    )
    .unwrap();

    assert!(signed.starts_with(unsigned));
    let extra = &signed[unsigned.len()..];
    assert!(extra.starts_with(":SIG "));
    assert_eq!(extra.matches('\n').count(), 1);
}
