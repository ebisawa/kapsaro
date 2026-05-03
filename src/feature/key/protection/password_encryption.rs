// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Password-based private key encryption/decryption using Argon2id + XChaCha20-Poly1305.

use super::encryption::{
    build_private_key_decrypt_error, decode_ciphertext_params, decrypt_private_key_plaintext,
    encrypt_serialized_private_key,
};
use super::password_key_derivation;
use crate::crypto::types::primitives::{HkdfSalt, PrivateKeyIkmSalt};
use crate::model::identifiers::{alg, format};
use crate::model::private_key::{
    PrivateKey, PrivateKeyAlgorithm, PrivateKeyPlaintext, PrivateKeyProtected,
};
use crate::support::codec::base64_public::{decode_base64url_nopad_array, encode_base64url_nopad};
use crate::support::secret::SecretString;
use crate::{Error, Result};

/// Build protected header for password-based PrivateKey encryption
fn build_protected_header(
    member_handle: &str,
    kid: &str,
    ikm_salt_b64: String,
    hkdf_salt_b64: String,
    created_at: &str,
    expires_at: &str,
) -> PrivateKeyProtected {
    PrivateKeyProtected {
        format: format::PRIVATE_KEY_V6.to_string(),
        subject_handle: member_handle.to_string(),
        kid: kid.to_string(),
        alg: PrivateKeyAlgorithm::Argon2id {
            ikm_salt: ikm_salt_b64,
            hkdf_salt: hkdf_salt_b64,
            aead: alg::AEAD_XCHACHA20_POLY1305.to_string(),
        },
        created_at: created_at.to_string(),
        expires_at: expires_at.to_string(),
    }
}

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
    let ikm_salt = password_key_derivation::generate_ikm_salt()?;
    let hkdf_salt = password_key_derivation::generate_hkdf_salt()?;
    let ikm_salt_b64 = encode_base64url_nopad(ikm_salt.as_bytes());
    let hkdf_salt_b64 = encode_base64url_nopad(hkdf_salt.as_bytes());

    let protected = build_protected_header(
        member_handle,
        kid,
        ikm_salt_b64,
        hkdf_salt_b64,
        created_at,
        expires_at,
    );

    let enc_key = password_key_derivation::derive_key_from_password(
        password, &ikm_salt, &hkdf_salt, kid, debug,
    )?;

    let encrypted = encrypt_serialized_private_key(
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
        PrivateKeyAlgorithm::Argon2id { aead, .. } => {
            if aead != alg::AEAD_XCHACHA20_POLY1305 {
                return Err(Error::Crypto {
                    message: format!(
                        "Unsupported AEAD algorithm '{}', expected '{}'",
                        aead,
                        alg::AEAD_XCHACHA20_POLY1305
                    ),
                    source: None,
                });
            }
        }
        _ => {
            return Err(Error::Crypto {
                message: "Expected Argon2id algorithm, got SSH-based".to_string(),
                source: None,
            });
        }
    }

    let ikm_salt_bytes: [u8; 32] =
        decode_base64url_nopad_array(private_key.protected.alg.ikm_salt(), "ikm_salt")?;
    let hkdf_salt_bytes: [u8; 32] =
        decode_base64url_nopad_array(private_key.protected.alg.hkdf_salt(), "hkdf_salt")?;
    let ikm_salt = PrivateKeyIkmSalt::new(ikm_salt_bytes);
    let hkdf_salt = HkdfSalt::new(hkdf_salt_bytes);
    let (nonce, ct, aad) = decode_ciphertext_params(private_key)?;

    let enc_key = password_key_derivation::derive_key_from_password(
        password,
        &ikm_salt,
        &hkdf_salt,
        &private_key.protected.kid,
        debug,
    )?;

    match decrypt_private_key_plaintext(
        &enc_key,
        &nonce,
        &aad,
        &ct,
        &private_key.protected.kid,
        debug,
        "decrypt_private_key_with_password",
    ) {
        Ok(plaintext) => Ok(plaintext),
        Err(error) => Err(build_private_key_decrypt_error(error)),
    }
}
