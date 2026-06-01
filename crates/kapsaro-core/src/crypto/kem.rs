// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key Encapsulation Mechanism (KEM) algorithms
//!
//! HPKE Base mode: X25519-HKDF-SHA256 + ChaCha20-Poly1305

use crate::crypto::build_crypto_operation_error;
use crate::crypto::rng::{fill_secret_array, hpke_sender_setup_rng};
use crate::crypto::types::data::{Aad, Ciphertext, Enc, Info, Plaintext};
use crate::Result;
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable,
    Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// X25519 secret key with Zeroizing memory protection
#[derive(Zeroize, ZeroizeOnDrop)]
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

fn serialize_private_key(private_key: &<Kem as KemTrait>::PrivateKey) -> Zeroizing<[u8; 32]> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    private_key.write_exact(bytes.as_mut());
    bytes
}

fn serialize_public_key(public_key: &<Kem as KemTrait>::PublicKey) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    public_key.write_exact(&mut bytes);
    bytes
}

/// Generate a new X25519 key pair using the HPKE KEM implementation.
pub fn generate_keypair() -> Result<(X25519SecretKey, X25519PublicKey)> {
    let keying_material = fill_secret_array::<32>()?;
    let (secret_key, public_key) = Kem::derive_keypair(keying_material.as_ref());
    Ok((
        X25519SecretKey::from_zeroizing(serialize_private_key(&secret_key)),
        X25519PublicKey::from_bytes(serialize_public_key(&public_key)),
    ))
}

/// Derive the public key for a secret key.
pub fn derive_public_key_from_secret(secret_key: &X25519SecretKey) -> Result<X25519PublicKey> {
    let secret_key_hpke = <Kem as KemTrait>::PrivateKey::from_bytes(secret_key.as_bytes())
        .map_err(|_| build_crypto_operation_error("Invalid recipient secret key"))?;
    let public_key_hpke = Kem::sk_to_pk(&secret_key_hpke);
    Ok(X25519PublicKey::from_bytes(serialize_public_key(
        &public_key_hpke,
    )))
}

/// Encrypts plaintext using HPKE Base mode.
/// Returns (enc: 32-byte encapsulated key, ciphertext with 16-byte tag).
pub fn seal_base(
    pk_recip: &X25519PublicKey,
    info: &Info,
    aad: &Aad,
    plaintext: &Plaintext,
) -> Result<(Enc, Ciphertext)> {
    let pk_recip_hpke = <Kem as KemTrait>::PublicKey::from_bytes(pk_recip.as_bytes())
        .map_err(|_| build_crypto_operation_error("Invalid recipient public key"))?;

    let mut csprng = hpke_sender_setup_rng()?;
    let (enc, mut sender_ctx) = hpke::setup_sender::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &pk_recip_hpke,
        info.as_bytes(),
        &mut csprng,
    )
    .map_err(|_| build_crypto_operation_error("HPKE setup sender failed"))?;
    csprng.ensure_consumed_exactly()?;

    let ciphertext = sender_ctx
        .seal(plaintext.as_bytes(), aad.as_bytes())
        .map_err(|_| build_crypto_operation_error("HPKE seal failed"))?;

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
        .map_err(|_| build_crypto_operation_error("Invalid recipient secret key"))?;

    let enc_parsed = <Kem as KemTrait>::EncappedKey::from_bytes(enc.as_bytes())
        .map_err(|_| build_crypto_operation_error("Invalid encapsulated key"))?;

    let mut receiver_ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk_recip_hpke,
        &enc_parsed,
        info.as_bytes(),
    )
    .map_err(|_| build_crypto_operation_error("HPKE setup receiver failed"))?;

    let plaintext = receiver_ctx
        .open(ciphertext.as_bytes(), aad.as_bytes())
        .map_err(|_| {
            build_crypto_operation_error("HPKE open failed (wrong key/info/AAD or tampered data)")
        })?;

    Ok(Zeroizing::new(Plaintext::from(plaintext)))
}
