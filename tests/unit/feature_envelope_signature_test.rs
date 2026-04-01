// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use super::*;
use crate::model::public_key::{
    Attestation, Identity, IdentityKeys, JwkOkpPublicKey, PublicKeyProtected,
};

fn make_dummy_signer_pub(kid: &str) -> PublicKey {
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
                        x: "dummy".to_string(),
                    },
                    sig: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: "Ed25519".to_string(),
                        x: "dummy".to_string(),
                    },
                },
                attestation: Attestation {
                    method: "test".to_string(),
                    pub_: "test".to_string(),
                    sig: "dummy".to_string(),
                },
            },
            binding_claims: None,
            expires_at: "2099-01-01T00:00:00Z".to_string(),
            created_at: Some("2026-01-01T00:00:00Z".to_string()),
        },
        signature: "dummy".to_string(),
    }
}

#[test]
fn test_sign_and_append_kv_sig_produces_sig_line() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let kid = "test-kid";
    let unsigned = ":SECRETENV_KV 3\n:HEAD {}\n:WRAP {}\nKEY token\n";

    let result = sign_and_append_kv_sig(
        unsigned,
        &signing_key,
        kid,
        make_dummy_signer_pub(kid),
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
fn test_sign_and_append_kv_sig_preserves_unsigned_content() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let unsigned = ":SECRETENV_KV 3\n:HEAD tok\n:WRAP tok\nA val\nB val\n";

    let signed = sign_and_append_kv_sig(
        unsigned,
        &signing_key,
        "kid",
        make_dummy_signer_pub("kid"),
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
