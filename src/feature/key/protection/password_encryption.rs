// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Password-based private key encryption/decryption using Argon2id + XChaCha20-Poly1305.

use super::encryption::build_private_key_decrypt_error;
use super::material::{
    build_argon2id_algorithm, build_private_key_protected, decode_ciphertext_params,
    decode_hkdf_salt, decode_ikm_salt, decrypt_private_key_plaintext,
    encrypt_private_key_plaintext, validate_aead_algorithm, PrivateKeyProtectionMaterial,
    PrivateKeyProtectionMetadata,
};
use super::password_key_derivation;
use crate::model::private_key::{PrivateKey, PrivateKeyAlgorithm, PrivateKeyPlaintext};
use crate::support::secret::SecretString;
use crate::{Error, Result};

/// Encrypt a private key with a password using Argon2id key derivation
pub fn encrypt_private_key_with_password(
    plaintext: &PrivateKeyPlaintext,
    member_handle: &str,
    kid: &str,
    created_at: &str,
    expires_at: &str,
    password: &SecretString,
    debug: bool,
) -> Result<PrivateKey> {
    let material = PrivateKeyProtectionMaterial::generate()?;
    let metadata = PrivateKeyProtectionMetadata {
        member_handle,
        kid,
        created_at,
        expires_at,
    };
    let protected = build_private_key_protected(metadata, build_argon2id_algorithm(&material));

    let enc_key = password_key_derivation::derive_key_from_password(
        password,
        &material.ikm_salt,
        &material.hkdf_salt,
        kid,
        debug,
    )?;

    let encrypted = encrypt_private_key_plaintext(
        plaintext,
        &enc_key,
        &protected,
        debug,
        "encrypt_private_key_with_password",
    )?;

    Ok(PrivateKey {
        protected,
        encrypted,
    })
}

/// Decrypt a private key that was encrypted with a password
pub fn decrypt_private_key_with_password(
    private_key: &PrivateKey,
    password: &SecretString,
    debug: bool,
) -> Result<PrivateKeyPlaintext> {
    match &private_key.protected.alg {
        PrivateKeyAlgorithm::Argon2id { aead, .. } => validate_aead_algorithm(aead)?,
        _ => {
            return Err(Error::Crypto {
                message: "Expected Argon2id algorithm, got SSH-based".to_string(),
                source: None,
            });
        }
    }

    let ikm_salt = decode_ikm_salt(private_key)?;
    let hkdf_salt = decode_hkdf_salt(private_key)?;
    let ciphertext = decode_ciphertext_params(private_key)?;

    let enc_key = password_key_derivation::derive_key_from_password(
        password,
        &ikm_salt,
        &hkdf_salt,
        &private_key.protected.kid,
        debug,
    )?;

    match decrypt_private_key_plaintext(
        &enc_key,
        &ciphertext,
        &private_key.protected.kid,
        debug,
        "decrypt_private_key_with_password",
    ) {
        Ok(plaintext) => Ok(plaintext),
        Err(error) => Err(build_private_key_decrypt_error(error)),
    }
}
