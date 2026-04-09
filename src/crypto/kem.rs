// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key Encapsulation Mechanism (KEM) algorithms
//!
//! HPKE Base mode: X25519-HKDF-SHA256 + ChaCha20-Poly1305

use crate::crypto::crypto_operation_failed;
use crate::crypto::types::data::{Aad, Ciphertext, Enc, Info, Plaintext};
use crate::model::verified::VerifiedPrivateKey;
use crate::support::base64url::b64_decode_secret_array;
use crate::Result;
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable,
    Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

/// X25519 secret key with Zeroizing memory protection
pub struct X25519SecretKey(Zeroizing<[u8; 32]>);

impl X25519SecretKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn from_zeroizing(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }
}

/// X25519 public key
#[derive(Clone, PartialEq, Eq)]
pub struct X25519PublicKey([u8; 32]);

impl X25519PublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create X25519PublicKey from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

/// Encrypts plaintext using HPKE Base mode.
/// Returns (enc: 32-byte encapsulated key, ciphertext with 16-byte tag).
pub fn seal_base(
    pk_recip: &X25519PublicKey,
    info: &Info,
    aad: &Aad,
    plaintext: &Plaintext,
) -> Result<(Enc, Ciphertext)> {
    let pk_recip_hpke = <Kem as KemTrait>::PublicKey::from_bytes(pk_recip.as_bytes())
        .map_err(|_| crypto_operation_failed("Invalid recipient public key"))?;

    let (enc, mut sender_ctx) = hpke::setup_sender::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &pk_recip_hpke,
        info.as_bytes(),
        &mut OsRng,
    )
    .map_err(|_| crypto_operation_failed("HPKE setup sender failed"))?;

    let ciphertext = sender_ctx
        .seal(plaintext.as_bytes(), aad.as_bytes())
        .map_err(|_| crypto_operation_failed("HPKE seal failed"))?;

    Ok((
        Enc::from(enc.to_bytes().to_vec()),
        Ciphertext::from(ciphertext),
    ))
}

/// Decrypts ciphertext using HPKE Base mode.
/// Returns plaintext wrapped in Zeroizing for secure memory clearing.
pub fn open_base(
    sk_recip: &X25519SecretKey,
    enc: &Enc,
    info: &Info,
    aad: &Aad,
    ciphertext: &Ciphertext,
) -> Result<Zeroizing<Plaintext>> {
    let sk_recip_hpke = <Kem as KemTrait>::PrivateKey::from_bytes(sk_recip.as_bytes())
        .map_err(|_| crypto_operation_failed("Invalid recipient secret key"))?;

    let enc_parsed = <Kem as KemTrait>::EncappedKey::from_bytes(enc.as_bytes())
        .map_err(|_| crypto_operation_failed("Invalid encapsulated key"))?;

    let mut receiver_ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk_recip_hpke,
        &enc_parsed,
        info.as_bytes(),
    )
    .map_err(|_| crypto_operation_failed("HPKE setup receiver failed"))?;

    let plaintext = receiver_ctx
        .open(ciphertext.as_bytes(), aad.as_bytes())
        .map_err(|_| {
            crypto_operation_failed("HPKE open failed (wrong key/info/AAD or tampered data)")
        })?;

    Ok(Zeroizing::new(Plaintext::from(plaintext)))
}

/// Decode KEM secret key from decrypted private key
///
/// This is a common helper for extracting the X25519 secret key from
/// a VerifiedPrivateKey structure.
pub fn decode_kem_secret_key(private_key: &VerifiedPrivateKey) -> Result<X25519SecretKey> {
    let kem_sk_bytes =
        b64_decode_secret_array(&private_key.document().keys.kem.d, "KEM private key")?;
    Ok(X25519SecretKey::from_zeroizing(kem_sk_bytes))
}
