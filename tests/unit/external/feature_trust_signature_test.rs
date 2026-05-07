// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for trust store signing

use ed25519_dalek::{SigningKey, VerifyingKey};
use secretenv::feature::key::material::generate_keypairs;
use secretenv::feature::trust::signature::sign_trust_store;
use secretenv::model::identifiers::format::TRUST_LOCAL_V4;
use secretenv::model::trust_store::TrustStoreProtected;
use secretenv::support::codec::base64_public::encode_base64url_nopad;

/// Build a minimal PublicKey JSON that passes schema + self-signature verification.
///
/// This is a lightweight helper for trust store tests only. It generates
/// real Ed25519 keys and creates a proper self-signed PublicKey document.
fn build_self_signed_public_key(
    member_handle: &str,
    signing_key: &SigningKey,
) -> (secretenv::model::public_key::PublicKey, String) {
    use secretenv::feature::key::public_key_document::{build_public_key, PublicKeyDocumentParams};
    use secretenv::model::identifiers::jwk;
    use secretenv::model::public_key::{Attestation, Identity, IdentityKeys, JwkOkpPublicKey};

    let verifying_key: VerifyingKey = signing_key.into();
    let sig_x = encode_base64url_nopad(&verifying_key.to_bytes());

    // Generate X25519 KEM key pair
    let keypairs = generate_keypairs().unwrap();
    let kem_x = encode_base64url_nopad(keypairs.kem_pk.as_bytes());

    let identity_keys = IdentityKeys {
        kem: JwkOkpPublicKey {
            kty: "OKP".to_string(),
            crv: jwk::CRV_X25519.to_string(),
            x: kem_x,
        },
        sig: JwkOkpPublicKey {
            kty: "OKP".to_string(),
            crv: jwk::CRV_ED25519.to_string(),
            x: sig_x,
        },
    };

    // Minimal attestation stub (not cryptographically valid, but sufficient
    // for trust store signature tests since verify_public_key_for_verification
    // will check self-sig and attestation)
    let attestation = Attestation {
        method: "ssh-sign".to_string(),
        pub_: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest".to_string(),
        sig: "stub".to_string(),
    };

    let identity = Identity {
        keys: identity_keys,
        attestation,
    };

    let now = time::OffsetDateTime::now_utc();
    let created_at = secretenv::support::time::format_timestamp_rfc3339(now).unwrap();
    let expires_at =
        secretenv::support::time::format_timestamp_rfc3339(now + time::Duration::days(365))
            .unwrap();

    let public_key = build_public_key(&PublicKeyDocumentParams {
        member_handle,
        identity,
        created_at: &created_at,
        expires_at: &expires_at,
        sig_sk: signing_key,
        debug: false,
        github_account: None,
    })
    .unwrap();

    let kid = public_key.protected.kid.clone();
    (public_key, kid)
}

#[test]
fn test_sign_trust_store_produces_valid_document() {
    let signing_key = SigningKey::from_bytes(&[5u8; 32]);
    let (_public_key, kid) = build_self_signed_public_key("alice@example.com", &signing_key);

    let protected = TrustStoreProtected {
        format: TRUST_LOCAL_V4.to_string(),
        owner_handle: "alice@example.com".to_string(),
        created_at: "2026-03-29T12:34:56Z".to_string(),
        updated_at: "2026-03-29T12:34:56Z".to_string(),
        known_keys: vec![],
        recipient_sets: Vec::new(),
    };

    let doc = sign_trust_store(&protected, &signing_key, &kid).unwrap();
    assert_eq!(doc.protected.format, TRUST_LOCAL_V4);
    assert_eq!(doc.signature.kid, kid);
    assert!(!doc.signature.sig.is_empty());
}
