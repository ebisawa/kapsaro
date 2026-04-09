// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Pure key material builders used during key generation.

use crate::model::identifiers::jwk::{self, CRV_ED25519, CRV_X25519};
use crate::model::private_key::{IdentityKeysPrivate, JwkOkpPrivateKey, PrivateKeyPlaintext};
use crate::model::public_key::{IdentityKeys, JwkOkpPublicKey};
use crate::Result;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

pub struct GeneratedKeypairs {
    pub kem_sk: X25519SecretKey,
    pub kem_pk: X25519PublicKey,
    pub sig_sk: SigningKey,
    pub sig_pk: VerifyingKey,
}

/// Generate a new key pair (KEM and signing keys).
pub fn generate_keypairs() -> Result<GeneratedKeypairs> {
    let kem_sk = X25519SecretKey::random_from_rng(OsRng);
    let kem_pk = X25519PublicKey::from(&kem_sk);

    let sig_sk = SigningKey::generate(&mut OsRng);
    let sig_pk: VerifyingKey = sig_sk.verifying_key();

    Ok(GeneratedKeypairs {
        kem_sk,
        kem_pk,
        sig_sk,
        sig_pk,
    })
}

/// Build identity keys from KEM and signing public keys.
pub fn build_identity_keys(
    kem_pk: &X25519PublicKey,
    sig_pk: &VerifyingKey,
) -> Result<IdentityKeys> {
    Ok(IdentityKeys {
        kem: JwkOkpPublicKey {
            kty: "OKP".to_string(),
            crv: CRV_X25519.to_string(),
            x: URL_SAFE_NO_PAD.encode(kem_pk.as_bytes()),
        },
        sig: JwkOkpPublicKey {
            kty: "OKP".to_string(),
            crv: CRV_ED25519.to_string(),
            x: URL_SAFE_NO_PAD.encode(sig_pk.as_bytes()),
        },
    })
}

/// Build private key plaintext from keypairs.
///
/// Note: base64::encode intermediates are not wrapped in Zeroizing.
/// Accepted risk: the String is moved directly into JwkOkpPrivateKey
/// which has #[zeroize(drop)]. A custom encoder would be disproportionate
/// for 32-byte key material.
pub fn build_private_key_plaintext(
    kem_sk: &X25519SecretKey,
    kem_pk: &X25519PublicKey,
    sig_sk: &SigningKey,
    sig_pk: &VerifyingKey,
) -> PrivateKeyPlaintext {
    PrivateKeyPlaintext {
        keys: IdentityKeysPrivate {
            kem: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: jwk::CRV_X25519.to_string(),
                x: URL_SAFE_NO_PAD.encode(kem_pk.as_bytes()),
                d: URL_SAFE_NO_PAD.encode(kem_sk.as_bytes()),
            },
            sig: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: jwk::CRV_ED25519.to_string(),
                x: URL_SAFE_NO_PAD.encode(sig_pk.as_bytes()),
                d: URL_SAFE_NO_PAD.encode(sig_sk.as_bytes()),
            },
        },
    }
}
