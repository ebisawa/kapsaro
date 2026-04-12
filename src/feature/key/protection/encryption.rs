// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH Key Protection for PrivateKey v4
//!
//! PrivateKey v4 must be encrypted with an SSH Ed25519 key.
//! This module implements the encryption and decryption process.

use super::key_derivation;
use crate::crypto::aead::xchacha;
use crate::crypto::types::data::{Aad, Ciphertext, Plaintext};
use crate::crypto::types::keys::XChaChaKey;
use crate::crypto::types::primitives::{Salt, XChaChaNonce};
use crate::feature::key::protection::binding::build_private_key_aad;
use crate::io::ssh::backend::SignatureBackend;
use crate::model::identifiers::{alg, format};
use crate::model::private_key::{
    EncryptedData, PrivateKey, PrivateKeyAlgorithm, PrivateKeyPlaintext, PrivateKeyProtected,
};
use crate::support::codec::base64_public::{
    decode_base64url_nopad_array, decode_base64url_nopad_ciphertext, encode_base64url_nopad,
};
use crate::support::kid::kid_display_lossy;
use crate::{Error, Result};
use tracing::debug;

/// Build protected header for PrivateKey encryption
fn build_protected_header(
    member_id: String,
    kid: String,
    ssh_fpr: String,
    salt: &Salt,
    created_at: String,
    expires_at: String,
) -> PrivateKeyProtected {
    PrivateKeyProtected {
        format: format::PRIVATE_KEY_V4.to_string(),
        member_id: member_id.clone(),
        kid: kid.clone(),
        alg: PrivateKeyAlgorithm::SshSig {
            fpr: ssh_fpr.clone(),
            salt: encode_base64url_nopad(salt.as_bytes()),
            aead: alg::AEAD_XCHACHA20_POLY1305.to_string(),
        },
        created_at: created_at.clone(),
        expires_at: expires_at.clone(),
    }
}

/// Serialize plaintext and encrypt with XChaCha20-Poly1305
pub(super) fn serialize_and_encrypt(
    plaintext: &PrivateKeyPlaintext,
    enc_key: &XChaChaKey,
    protected: &PrivateKeyProtected,
    debug: bool,
    caller: &str,
) -> Result<EncryptedData> {
    // Serialize plaintext
    let plaintext_json = serde_json::to_vec(plaintext).map_err(|e| Error::Crypto {
        message: format!("Failed to serialize plaintext: {}", e),
        source: Some(Box::new(e)),
    })?;
    let plaintext = Plaintext::from(plaintext_json);

    // Build AAD from protected header and encrypt
    let aad = build_private_key_aad(protected)?;
    if debug {
        debug!(
            "[CRYPTO] XChaCha20-Poly1305: {}: encrypt (kid: {})",
            caller,
            kid_display_lossy(&protected.kid)
        );
    }
    let (ct, nonce) = xchacha::encrypt_with_nonce(enc_key, &plaintext, &aad)?;

    Ok(EncryptedData {
        nonce: encode_base64url_nopad(nonce.as_bytes()),
        ct: encode_base64url_nopad(ct.as_bytes()),
    })
}

/// Decode encryption parameters from PrivateKey
pub(super) fn decode_encryption_params(
    private_key: &PrivateKey,
) -> Result<(Salt, XChaChaNonce, Ciphertext, Aad)> {
    // Decode salt
    let salt_bytes: [u8; 16] =
        decode_base64url_nopad_array(private_key.protected.alg.salt(), "salt")?;
    let salt = Salt::new(salt_bytes);

    // Decode nonce and ciphertext
    let nonce_bytes: [u8; 24] =
        decode_base64url_nopad_array(&private_key.encrypted.nonce, "nonce")?;
    let nonce = XChaChaNonce::new(nonce_bytes);
    let ct = decode_base64url_nopad_ciphertext(&private_key.encrypted.ct, "ct")?;

    // Build AAD from protected header
    let aad = build_private_key_aad(&private_key.protected)?;

    Ok((salt, nonce, ct, aad))
}

/// Decrypt and deserialize plaintext
pub(super) fn decrypt_and_deserialize(
    enc_key: &XChaChaKey,
    nonce: &XChaChaNonce,
    aad: &Aad,
    ct: &Ciphertext,
    kid: &str,
    debug: bool,
    caller: &str,
) -> Result<PrivateKeyPlaintext> {
    if debug {
        debug!(
            "[CRYPTO] XChaCha20-Poly1305: {}: decrypt (kid: {})",
            caller,
            kid_display_lossy(kid)
        );
    }
    let plaintext_json = xchacha::decrypt(enc_key, nonce, aad, ct)?;

    serde_json::from_slice(plaintext_json.as_bytes()).map_err(|e| Error::Crypto {
        message: format!("Failed to deserialize plaintext: {}", e),
        source: Some(Box::new(e)),
    })
}

/// Parameters for encrypting a private key with SSH key.
pub struct PrivateKeyEncryptionParams<'a> {
    pub plaintext: &'a PrivateKeyPlaintext,
    pub member_id: String,
    pub kid: String,
    pub backend: &'a dyn SignatureBackend,
    pub ssh_pubkey: &'a str,
    pub ssh_fpr: String,
    pub created_at: String,
    pub expires_at: String,
    pub debug: bool,
}

/// Encrypt PrivateKey with SSH key
pub fn encrypt_private_key(params: &PrivateKeyEncryptionParams<'_>) -> Result<PrivateKey> {
    // Generate salt
    let salt = key_derivation::generate_salt();

    // Build protected header
    let protected = build_protected_header(
        params.member_id.clone(),
        params.kid.clone(),
        params.ssh_fpr.clone(),
        &salt,
        params.created_at.clone(),
        params.expires_at.clone(),
    );

    // Derive encryption key
    let enc_key = key_derivation::derive_key_from_ssh(
        &params.kid,
        &salt,
        params.backend,
        params.ssh_pubkey,
        params.debug,
    )?;

    // Serialize and encrypt
    let encrypted = serialize_and_encrypt(
        params.plaintext,
        &enc_key,
        &protected,
        params.debug,
        "encrypt_private_key",
    )?;

    Ok(PrivateKey {
        protected,
        encrypted,
    })
}

/// Decrypt PrivateKey with SSH key
pub fn decrypt_private_key(
    private_key: &PrivateKey,
    backend: &dyn SignatureBackend,
    ssh_pubkey: &str,
    debug: bool,
) -> Result<PrivateKeyPlaintext> {
    // Decode encryption parameters
    let (salt, nonce, ct, aad) = decode_encryption_params(private_key)?;

    // Derive key
    let enc_key = key_derivation::derive_key_from_ssh(
        &private_key.protected.kid,
        &salt,
        backend,
        ssh_pubkey,
        debug,
    )?;

    // Decrypt and deserialize
    decrypt_and_deserialize(
        &enc_key,
        &nonce,
        &aad,
        &ct,
        &private_key.protected.kid,
        debug,
        "decrypt_private_key",
    )
}
