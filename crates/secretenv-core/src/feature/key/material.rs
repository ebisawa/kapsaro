// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Pure key material builders used during key generation.

use crate::crypto::kem::{
    derive_public_key_from_secret, generate_keypair as generate_kem_keypair, X25519PublicKey,
    X25519SecretKey,
};
use crate::crypto::rng::fill_secret_array;
use crate::format::codec::base64_public::{decode_base64url_nopad_array, encode_base64url_nopad};
use crate::format::codec::base64_secret::{
    decode_base64url_nopad_secret_32, encode_base64url_nopad_secret_32,
};
use crate::model::private_key::{IdentityKeysPrivate, JwkOkpPrivateKey, PrivateKeyPlaintext};
use crate::model::public_key::{IdentityKeys, JwkOkpPublicKey};
use crate::model::wire::jwk::{self, CURVE_ED25519, CURVE_X25519};
use crate::support::secret::SecretArray;
use crate::{Error, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct KeypairMaterial {
    pub kem_sk: X25519SecretKey,
    #[zeroize(skip)]
    pub kem_pk: X25519PublicKey,
    pub sig_sk: SigningKey,
    #[zeroize(skip)]
    pub sig_pk: VerifyingKey,
}

/// Generate a new key pair (KEM and signing keys).
pub fn generate_keypairs() -> Result<KeypairMaterial> {
    let (kem_sk, kem_pk) = generate_kem_keypair()?;

    let sig_seed = fill_secret_array::<32>()?;
    let sig_sk = SigningKey::from_bytes(&sig_seed);
    let sig_pk: VerifyingKey = sig_sk.verifying_key();

    Ok(KeypairMaterial {
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
            crv: CURVE_X25519.to_string(),
            x: encode_base64url_nopad(kem_pk.as_bytes()),
        },
        sig: JwkOkpPublicKey {
            kty: "OKP".to_string(),
            crv: CURVE_ED25519.to_string(),
            x: encode_base64url_nopad(sig_pk.as_bytes()),
        },
    })
}

/// Build private key plaintext from keypairs.
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
                crv: jwk::CURVE_X25519.to_string(),
                x: encode_base64url_nopad(kem_pk.as_bytes()),
                d: encode_base64url_nopad_secret_32(&SecretArray::new(*kem_sk.as_bytes()))
                    .into_plain_string_for_output(),
            },
            sig: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: jwk::CURVE_ED25519.to_string(),
                x: encode_base64url_nopad(sig_pk.as_bytes()),
                d: encode_base64url_nopad_secret_32(&SecretArray::new(*sig_sk.as_bytes()))
                    .into_plain_string_for_output(),
            },
        },
    }
}

/// Validate an OKP private/public key pair shape.
pub fn validate_okp_key(
    kty: &str,
    crv: &str,
    expected_crv: &str,
    d: &str,
    x: &str,
    label: &str,
) -> Result<(SecretArray<32>, [u8; 32])> {
    if kty != "OKP" {
        return Err(Error::build_crypto_error(format!(
            "Invalid {} key type: expected 'OKP', got '{}'",
            label, kty
        )));
    }
    if crv != expected_crv {
        return Err(Error::build_crypto_error(format!(
            "Invalid {} curve: expected '{}', got '{}'",
            label, expected_crv, crv
        )));
    }
    let d_bytes = decode_base64url_nopad_secret_32(d, &format!("{} private key", label))?;
    let x_bytes = decode_base64url_nopad_array(x, &format!("{} public key", label))?;
    Ok((d_bytes, x_bytes))
}

/// Validate that an Ed25519 private key derives to the provided public key.
pub fn validate_ed25519_consistency(
    sig_d_bytes: &SecretArray<32>,
    sig_x_bytes: &[u8; 32],
) -> Result<()> {
    let signing_key = SigningKey::from_bytes(sig_d_bytes.as_array());
    let derived_vk = signing_key.verifying_key();
    let derived_x_bytes = derived_vk.as_bytes();
    if derived_x_bytes != sig_x_bytes {
        return Err(Error::build_crypto_error(
            "Ed25519 key pair inconsistency: private key does not derive to public key".to_string(),
        ));
    }
    Ok(())
}

/// Validate that an X25519 private key derives to the provided public key.
pub fn validate_x25519_consistency(
    kem_d_bytes: &SecretArray<32>,
    kem_x_bytes: &[u8; 32],
) -> Result<()> {
    let secret_key = X25519SecretKey::from_bytes(*kem_d_bytes.as_array());
    let derived_public = derive_public_key_from_secret(&secret_key)?;
    if derived_public.as_bytes() != kem_x_bytes {
        return Err(Error::build_crypto_error(
            "X25519 key pair inconsistency: private key does not derive to public key".to_string(),
        ));
    }
    Ok(())
}

/// Validate private key plaintext key material.
pub(crate) fn validate_private_key_material(plaintext: &PrivateKeyPlaintext) -> Result<()> {
    let kem = &plaintext.keys.kem;
    let (kem_d_bytes, kem_x_bytes) =
        validate_okp_key(&kem.kty, &kem.crv, jwk::CURVE_X25519, &kem.d, &kem.x, "KEM")?;
    validate_x25519_consistency(&kem_d_bytes, &kem_x_bytes)?;

    let sig = &plaintext.keys.sig;
    let (sig_d_bytes, sig_x_bytes) = validate_okp_key(
        &sig.kty,
        &sig.crv,
        jwk::CURVE_ED25519,
        &sig.d,
        &sig.x,
        "Sig",
    )?;
    validate_ed25519_consistency(&sig_d_bytes, &sig_x_bytes)?;

    Ok(())
}
