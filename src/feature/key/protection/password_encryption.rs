// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Password-based private key encryption/decryption using Argon2id + XChaCha20-Poly1305.

use super::encryption::{decode_encryption_params, decrypt_and_deserialize, serialize_and_encrypt};
use super::password_key_derivation;
use crate::model::identifiers::{alg, format};
use crate::model::private_key::{
    PrivateKey, PrivateKeyAlgorithm, PrivateKeyPlaintext, PrivateKeyProtected,
};
use crate::support::codec::base64_public::encode_base64url_nopad;
use crate::{Error, Result};

/// Build protected header for password-based PrivateKey encryption
fn build_protected_header(
    member_id: &str,
    kid: &str,
    salt: &crate::crypto::types::primitives::Salt,
    created_at: &str,
    expires_at: &str,
) -> PrivateKeyProtected {
    PrivateKeyProtected {
        format: format::PRIVATE_KEY_V4.to_string(),
        member_id: member_id.to_string(),
        kid: kid.to_string(),
        alg: PrivateKeyAlgorithm::Argon2id {
            salt: encode_base64url_nopad(salt.as_bytes()),
            aead: alg::AEAD_XCHACHA20_POLY1305.to_string(),
        },
        created_at: created_at.to_string(),
        expires_at: expires_at.to_string(),
    }
}

/// Encrypt a private key with a password using Argon2id key derivation
pub fn encrypt_private_key_with_password(
    plaintext: &PrivateKeyPlaintext,
    member_id: &str,
    kid: &str,
    created_at: &str,
    expires_at: &str,
    password: &str,
    debug: bool,
) -> Result<PrivateKey> {
    let salt = password_key_derivation::generate_salt();

    let protected = build_protected_header(member_id, kid, &salt, created_at, expires_at);

    let enc_key = password_key_derivation::derive_key_from_password(password, &salt, kid, debug)?;

    let encrypted = serialize_and_encrypt(
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
    password: &str,
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

    let (salt, nonce, ct, aad) = decode_encryption_params(private_key)?;

    let enc_key = password_key_derivation::derive_key_from_password(
        password,
        &salt,
        &private_key.protected.kid,
        debug,
    )?;

    decrypt_and_deserialize(
        &enc_key,
        &nonce,
        &aad,
        &ct,
        &private_key.protected.kid,
        debug,
        "decrypt_private_key_with_password",
    )
}
