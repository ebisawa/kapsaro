// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH Key Protection for PrivateKey v5
//!
//! PrivateKey v5 must be encrypted with an SSH Ed25519 key.
//! This module implements the encryption and decryption process.

use super::key_derivation;
use crate::crypto::aead::xchacha;
use crate::crypto::types::data::{Aad, Ciphertext, Plaintext};
use crate::crypto::types::keys::XChaChaKey;
use crate::crypto::types::primitives::{HkdfSalt, XChaChaNonce};
use crate::feature::key::protection::binding::build_private_key_aad;
use crate::io::ssh::backend::SignatureBackend;
use crate::io::ssh::protocol::fingerprint::build_sha256_fingerprint;
use crate::model::identifiers::{alg, format};
use crate::model::private_key::{
    PrivateKey, PrivateKeyAlgorithm, PrivateKeyEncData, PrivateKeyPlaintext, PrivateKeyProtected,
};
use crate::support::codec::base64_public::{
    decode_base64url_nopad_array, decode_base64url_nopad_ciphertext, encode_base64url_nopad,
};
use crate::support::kid::format_kid_display_lossy;
use crate::{Error, Result};
use tracing::debug;

/// Build protected header for PrivateKey encryption
fn build_protected_header(
    member_id: String,
    kid: String,
    ssh_fpr: String,
    ikm_salt_b64: String,
    hkdf_salt_b64: String,
    created_at: String,
    expires_at: String,
) -> PrivateKeyProtected {
    PrivateKeyProtected {
        format: format::PRIVATE_KEY_V5.to_string(),
        member_id: member_id.clone(),
        kid: kid.clone(),
        alg: PrivateKeyAlgorithm::SshSig {
            fpr: ssh_fpr.clone(),
            ikm_salt: ikm_salt_b64,
            hkdf_salt: hkdf_salt_b64,
            aead: alg::AEAD_XCHACHA20_POLY1305.to_string(),
        },
        created_at: created_at.clone(),
        expires_at: expires_at.clone(),
    }
}

/// Serialize plaintext and encrypt with XChaCha20-Poly1305
pub(super) fn encrypt_serialized_private_key(
    plaintext: &PrivateKeyPlaintext,
    enc_key: &XChaChaKey,
    protected: &PrivateKeyProtected,
    debug: bool,
    caller: &str,
) -> Result<PrivateKeyEncData> {
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
            format_kid_display_lossy(&protected.kid)
        );
    }
    let (ct, nonce) = xchacha::encrypt_with_nonce(enc_key, &plaintext, &aad)?;

    Ok(PrivateKeyEncData {
        nonce: encode_base64url_nopad(nonce.as_bytes()),
        ct: encode_base64url_nopad(ct.as_bytes()),
    })
}

/// Decode ciphertext parameters from PrivateKey.
pub(super) fn decode_ciphertext_params(
    private_key: &PrivateKey,
) -> Result<(XChaChaNonce, Ciphertext, Aad)> {
    let nonce_bytes: [u8; 24] =
        decode_base64url_nopad_array(&private_key.encrypted.nonce, "nonce")?;
    let nonce = XChaChaNonce::new(nonce_bytes);
    let ct = decode_base64url_nopad_ciphertext(&private_key.encrypted.ct, "ct")?;

    // Build AAD from protected header
    let aad = build_private_key_aad(&private_key.protected)?;

    Ok((nonce, ct, aad))
}

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
            return Err(Error::Crypto {
                message: "Expected SshSig algorithm for SSH-based decryption".to_string(),
                source: None,
            });
        }
    };
    let actual = build_sha256_fingerprint(ssh_pubkey)?;
    let normalized_expected = normalize_fingerprint_prefix(expected);
    let normalized_actual = normalize_fingerprint_prefix(&actual);

    if normalized_expected == normalized_actual {
        return Ok(());
    }

    Err(Error::Crypto {
        message: format!(
            "E_PRIVATE_KEY_DECRYPT_FAILED: SSH public key fingerprint mismatch: expected '{}', got '{}'",
            expected, actual
        ),
        source: None,
    })
}

fn validate_ssh_protection_algorithm(private_key: &PrivateKey) -> Result<()> {
    match &private_key.protected.alg {
        PrivateKeyAlgorithm::SshSig { aead, .. } => {
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
            Ok(())
        }
        _ => Err(Error::Crypto {
            message: "Expected SshSig algorithm for SSH-based decryption".to_string(),
            source: None,
        }),
    }
}

/// Decrypt and deserialize plaintext
pub(super) fn decrypt_private_key_plaintext(
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
            format_kid_display_lossy(kid)
        );
    }
    let plaintext_json = xchacha::decrypt(enc_key, nonce, aad, ct)?;

    serde_json::from_slice(plaintext_json.as_bytes()).map_err(|_| Error::Crypto {
        message: "Failed to deserialize plaintext".to_string(),
        source: None,
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
    let ikm_salt = key_derivation::generate_ikm_salt()?;
    let hkdf_salt = key_derivation::generate_hkdf_salt()?;
    let ikm_salt_b64 = encode_base64url_nopad(ikm_salt.as_bytes());
    let hkdf_salt_b64 = encode_base64url_nopad(hkdf_salt.as_bytes());

    // Build protected header
    let protected = build_protected_header(
        params.member_id.clone(),
        params.kid.clone(),
        params.ssh_fpr.clone(),
        ikm_salt_b64.clone(),
        hkdf_salt_b64,
        params.created_at.clone(),
        params.expires_at.clone(),
    );

    // Derive encryption key
    let enc_key = key_derivation::derive_key_from_ssh(
        &params.kid,
        &ikm_salt_b64,
        &hkdf_salt,
        params.backend,
        params.ssh_pubkey,
        params.debug,
    )?;

    // Serialize and encrypt
    let encrypted = encrypt_serialized_private_key(
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

    let hkdf_salt_bytes: [u8; 32] =
        decode_base64url_nopad_array(private_key.protected.alg.hkdf_salt(), "hkdf_salt")?;
    let hkdf_salt = HkdfSalt::new(hkdf_salt_bytes);
    let ikm_salt_b64 = private_key.protected.alg.ikm_salt();
    let (nonce, ct, aad) = decode_ciphertext_params(private_key)?;

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
        &nonce,
        &aad,
        &ct,
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
    Error::Crypto {
        message: "E_PRIVATE_KEY_DECRYPT_FAILED: private key decryption failed".to_string(),
        source: Some(Box::new(error)),
    }
}
