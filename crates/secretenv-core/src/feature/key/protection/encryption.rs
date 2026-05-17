// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH Key Protection for PrivateKey v7
//!
//! PrivateKey v7 must be encrypted with an SSH Ed25519 key.
//! This module implements the encryption and decryption process.

use super::key_derivation;
use super::material::{
    build_private_key_protected, build_sshsig_algorithm, decode_ciphertext_params,
    decode_hkdf_salt, decrypt_private_key_plaintext, encrypt_private_key_plaintext,
    validate_aead_algorithm, PrivateKeyProtectionMaterial, PrivateKeyProtectionMetadata,
};
use crate::io::ssh::backend::SignatureBackend;
use crate::io::ssh::protocol::fingerprint::build_sha256_fingerprint;
use crate::model::private_key::{PrivateKey, PrivateKeyAlgorithm, PrivateKeyPlaintext};
use crate::{Error, Result};

fn normalize_fingerprint_prefix(fingerprint: &str) -> String {
    match fingerprint.get(..7) {
        Some(prefix) if prefix.eq_ignore_ascii_case("SHA256:") => {
            format!("SHA256:{}", &fingerprint[7..])
        }
        _ => fingerprint.to_string(),
    }
}

fn verify_ssh_fingerprint_matches(private_key: &PrivateKey, ssh_pubkey: &str) -> Result<()> {
    let expected = match &private_key.protected.alg {
        PrivateKeyAlgorithm::SshSig { fpr, .. } => fpr,
        _ => {
            return Err(Error::build_crypto_error(
                "Expected SshSig algorithm for SSH-based decryption".to_string(),
            ));
        }
    };
    let actual = build_sha256_fingerprint(ssh_pubkey)?;
    let normalized_expected = normalize_fingerprint_prefix(expected);
    let normalized_actual = normalize_fingerprint_prefix(&actual);

    if normalized_expected == normalized_actual {
        return Ok(());
    }

    Err(Error::build_crypto_error(format!(
            "E_PRIVATE_KEY_DECRYPT_FAILED: SSH public key fingerprint mismatch: expected '{}', got '{}'",
            expected, actual
        )))
}

fn validate_ssh_protection_algorithm(private_key: &PrivateKey) -> Result<()> {
    match &private_key.protected.alg {
        PrivateKeyAlgorithm::SshSig { aead, .. } => validate_aead_algorithm(aead),
        _ => Err(Error::build_crypto_error(
            "Expected SshSig algorithm for SSH-based decryption".to_string(),
        )),
    }
}

/// Parameters for encrypting a private key with SSH key.
pub struct PrivateKeyEncryptionParams<'a> {
    pub plaintext: &'a PrivateKeyPlaintext,
    pub member_handle: String,
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
    let material = PrivateKeyProtectionMaterial::generate()?;
    let metadata = PrivateKeyProtectionMetadata {
        member_handle: &params.member_handle,
        kid: &params.kid,
        created_at: &params.created_at,
        expires_at: &params.expires_at,
    };
    let protected =
        build_private_key_protected(metadata, build_sshsig_algorithm(&params.ssh_fpr, &material));

    let enc_key = key_derivation::derive_key_from_ssh(
        &params.kid,
        material.ikm_salt_b64(),
        &material.hkdf_salt,
        params.backend,
        params.ssh_pubkey,
        params.debug,
    )?;

    let encrypted = encrypt_private_key_plaintext(
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
    validate_ssh_protection_algorithm(private_key)?;
    verify_ssh_fingerprint_matches(private_key, ssh_pubkey)?;

    let hkdf_salt = decode_hkdf_salt(private_key)?;
    let ikm_salt_b64 = private_key.protected.alg.ikm_salt();
    let ciphertext = decode_ciphertext_params(private_key)?;

    let derived = key_derivation::derive_key_for_private_key_use(
        &private_key.protected.kid,
        ikm_salt_b64,
        &hkdf_salt,
        backend,
        ssh_pubkey,
        debug,
    )?;

    match decrypt_private_key_plaintext(
        &derived.enc_key,
        &ciphertext,
        &private_key.protected.kid,
        debug,
        "decrypt_private_key",
    ) {
        Ok(plaintext) => Ok(plaintext),
        Err(error) => {
            enforce_private_key_use_determinism(
                private_key,
                backend,
                ssh_pubkey,
                &derived.raw_sig,
                debug,
            )?;
            Err(build_private_key_decrypt_error(error))
        }
    }
}

fn enforce_private_key_use_determinism(
    private_key: &PrivateKey,
    backend: &dyn SignatureBackend,
    ssh_pubkey: &str,
    raw_sig: &crate::io::ssh::protocol::types::Ed25519RawSignature,
    debug: bool,
) -> Result<()> {
    key_derivation::enforce_private_key_use_signature_determinism(
        &private_key.protected.kid,
        private_key.protected.alg.ikm_salt(),
        backend,
        ssh_pubkey,
        raw_sig,
        debug,
    )
}

pub(super) fn build_private_key_decrypt_error(error: Error) -> Error {
    Error::build_crypto_error_with_source(
        "E_PRIVATE_KEY_DECRYPT_FAILED: private key decryption failed".to_string(),
        error,
    )
}
