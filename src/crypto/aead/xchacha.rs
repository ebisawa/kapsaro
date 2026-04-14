// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! XChaCha20-Poly1305 AEAD encryption
//!
//! XChaCha20-Poly1305 is the primary AEAD algorithm for v3.
//! - 24-byte nonce (vs 12-byte for AES-256-GCM)
//! - Extended nonce space prevents nonce reuse
//! - ChaCha20 stream cipher + Poly1305 MAC

use crate::crypto::crypto_operation_failed;
use crate::crypto::rng::fill_random_bytes;
use crate::crypto::types::data::{Aad, Ciphertext, Plaintext};
use crate::crypto::types::keys::XChaChaKey;
use crate::crypto::types::primitives::XChaChaNonce;
use crate::Result;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};
use zeroize::Zeroizing;

/// Nonce size for XChaCha20-Poly1305 (24 bytes)
pub const NONCE_SIZE: usize = 24;

/// Encrypt plaintext with XChaCha20-Poly1305 (low-level API with explicit nonce)
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `nonce` - 24-byte nonce (must be unique for each encryption with same key)
/// * `aad` - Additional authenticated data (not encrypted, but authenticated)
/// * `plaintext` - Data to encrypt
///
/// # Returns
/// Ciphertext with appended 16-byte Poly1305 tag
///
/// # Errors
/// Returns `Error::Crypto` if encryption fails
pub fn encrypt(
    key: &XChaChaKey,
    nonce: &XChaChaNonce,
    aad: &Aad,
    plaintext: &Plaintext,
) -> Result<Ciphertext> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

    let payload = Payload {
        msg: plaintext.as_bytes(),
        aad: aad.as_bytes(),
    };

    cipher
        .encrypt(nonce.as_bytes().into(), payload)
        .map(Ciphertext::from)
        .map_err(|_| crypto_operation_failed("XChaCha20-Poly1305 encryption failed"))
}

/// Decrypt ciphertext with XChaCha20-Poly1305 (low-level API with explicit nonce)
///
/// # Arguments
/// * `key` - 32-byte encryption key (same as used for encryption)
/// * `nonce` - 24-byte nonce (same as used for encryption)
/// * `aad` - Additional authenticated data (same as used for encryption)
/// * `ciphertext` - Encrypted data with appended Poly1305 tag
///
/// # Returns
/// Zeroizing plaintext (automatically zeroed on drop)
///
/// # Errors
/// Returns `Error::Crypto` if:
/// - Authentication tag is invalid (tampered ciphertext)
/// - Key is incorrect
/// - Nonce is incorrect
/// - AAD doesn't match
pub fn decrypt(
    key: &XChaChaKey,
    nonce: &XChaChaNonce,
    aad: &Aad,
    ciphertext: &Ciphertext,
) -> Result<Zeroizing<Plaintext>> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

    let payload = Payload {
        msg: ciphertext.as_bytes(),
        aad: aad.as_bytes(),
    };

    cipher
        .decrypt(nonce.as_bytes().into(), payload)
        .map(|v| Zeroizing::new(Plaintext::from(v)))
        .map_err(|_| crypto_operation_failed("XChaCha20-Poly1305 decryption failed"))
}

/// Encrypt plaintext with XChaCha20-Poly1305 (high-level API with auto-generated nonce)
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data (not encrypted, but authenticated)
///
/// # Returns
/// Tuple of (ciphertext, nonce)
///
/// # Errors
/// Returns `Error::Crypto` if encryption fails
pub fn encrypt_with_nonce(
    key: &XChaChaKey,
    plaintext: &Plaintext,
    aad: &Aad,
) -> Result<(Ciphertext, XChaChaNonce)> {
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    fill_random_bytes(&mut nonce_bytes)?;
    let nonce = XChaChaNonce::new(nonce_bytes);

    let ciphertext = encrypt(key, &nonce, aad, plaintext)?;
    Ok((ciphertext, nonce))
}
