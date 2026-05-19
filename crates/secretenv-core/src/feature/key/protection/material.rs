// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared PrivateKey protection material and AEAD helpers.

use crate::crypto::aead::xchacha;
use crate::crypto::rng::fill_random_array;
use crate::crypto::types::data::{Aad, Ciphertext, Plaintext};
use crate::crypto::types::keys::XChaChaKey;
use crate::crypto::types::primitives::{HkdfSalt, PrivateKeyIkmSalt, XChaChaNonce};
use crate::feature::key::protection::binding::build_private_key_aad;
use crate::model::private_key::{
    PrivateKey, PrivateKeyAlgorithm, PrivateKeyEncData, PrivateKeyPlaintext, PrivateKeyProtected,
};
use crate::model::wire::{algorithm, format};
use crate::support::codec::base64_public::{
    decode_base64url_nopad_array, decode_base64url_nopad_ciphertext, encode_base64url_nopad,
};
use crate::support::kid::format_kid_half_display_lossy;
use crate::{Error, Result};
use tracing::debug;

pub(super) struct PrivateKeyProtectionMetadata<'a> {
    pub(super) member_handle: &'a str,
    pub(super) kid: &'a str,
    pub(super) created_at: &'a str,
    pub(super) expires_at: &'a str,
}

pub(super) struct FreshPrivateKeyProtectionMaterial {
    pub(super) ikm_salt: PrivateKeyIkmSalt,
    pub(super) hkdf_salt: HkdfSalt,
    ikm_salt_b64: String,
    hkdf_salt_b64: String,
}

impl FreshPrivateKeyProtectionMaterial {
    pub(super) fn generate() -> Result<Self> {
        Self::new(
            PrivateKeyIkmSalt::new(fill_random_array::<32>()?),
            HkdfSalt::new(fill_random_array::<32>()?),
        )
    }

    fn new(ikm_salt: PrivateKeyIkmSalt, hkdf_salt: HkdfSalt) -> Result<Self> {
        let ikm_salt_b64 = encode_base64url_nopad(ikm_salt.as_bytes());
        let hkdf_salt_b64 = encode_base64url_nopad(hkdf_salt.as_bytes());
        Ok(Self {
            ikm_salt,
            hkdf_salt,
            ikm_salt_b64,
            hkdf_salt_b64,
        })
    }

    pub(super) fn ikm_salt_b64(&self) -> &str {
        &self.ikm_salt_b64
    }

    pub(super) fn hkdf_salt_b64(&self) -> &str {
        &self.hkdf_salt_b64
    }
}

pub(super) struct PrivateKeyCiphertextParams {
    pub(super) nonce: XChaChaNonce,
    pub(super) ct: Ciphertext,
    pub(super) aad: Aad,
}

pub(super) fn build_private_key_protected(
    metadata: PrivateKeyProtectionMetadata<'_>,
    alg: PrivateKeyAlgorithm,
) -> PrivateKeyProtected {
    PrivateKeyProtected {
        format: format::PRIVATE_KEY_V7.to_string(),
        subject_handle: metadata.member_handle.to_string(),
        kid: metadata.kid.to_string(),
        alg,
        created_at: metadata.created_at.to_string(),
        expires_at: metadata.expires_at.to_string(),
    }
}

pub(super) fn build_sshsig_algorithm(
    ssh_fpr: &str,
    material: &FreshPrivateKeyProtectionMaterial,
) -> PrivateKeyAlgorithm {
    PrivateKeyAlgorithm::SshSig {
        fpr: ssh_fpr.to_string(),
        ikm_salt: material.ikm_salt_b64().to_string(),
        hkdf_salt: material.hkdf_salt_b64().to_string(),
        aead: algorithm::AEAD_XCHACHA20_POLY1305.to_string(),
    }
}

pub(super) fn build_argon2id_algorithm(
    material: &FreshPrivateKeyProtectionMaterial,
) -> PrivateKeyAlgorithm {
    PrivateKeyAlgorithm::Argon2id {
        ikm_salt: material.ikm_salt_b64().to_string(),
        hkdf_salt: material.hkdf_salt_b64().to_string(),
        aead: algorithm::AEAD_XCHACHA20_POLY1305.to_string(),
    }
}

pub(super) fn validate_aead_algorithm(aead: &str) -> Result<()> {
    if aead == algorithm::AEAD_XCHACHA20_POLY1305 {
        return Ok(());
    }
    Err(Error::build_crypto_error(format!(
        "Unsupported AEAD algorithm '{}', expected '{}'",
        aead,
        algorithm::AEAD_XCHACHA20_POLY1305
    )))
}

pub(super) fn decode_hkdf_salt(private_key: &PrivateKey) -> Result<HkdfSalt> {
    let bytes: [u8; 32] =
        decode_base64url_nopad_array(private_key.protected.alg.hkdf_salt(), "hkdf_salt")?;
    Ok(HkdfSalt::new(bytes))
}

pub(super) fn decode_ikm_salt(private_key: &PrivateKey) -> Result<PrivateKeyIkmSalt> {
    let bytes: [u8; 32] =
        decode_base64url_nopad_array(private_key.protected.alg.ikm_salt(), "ikm_salt")?;
    Ok(PrivateKeyIkmSalt::new(bytes))
}

pub(super) fn encrypt_private_key_plaintext(
    plaintext: &PrivateKeyPlaintext,
    enc_key: &XChaChaKey,
    protected: &PrivateKeyProtected,
    debug_enabled: bool,
    caller: &str,
) -> Result<PrivateKeyEncData> {
    let plaintext_json = serde_json::to_vec(plaintext).map_err(|e| {
        Error::build_crypto_error_with_source(format!("Failed to serialize plaintext: {}", e), e)
    })?;
    let plaintext = Plaintext::from(plaintext_json);
    let aad = build_private_key_aad(protected)?;
    if debug_enabled {
        debug!(
            "[CRYPTO] XChaCha20-Poly1305: {}: encrypt (kid: {})",
            caller,
            format_kid_half_display_lossy(&protected.kid)
        );
    }
    let (ct, nonce) = xchacha::encrypt_with_nonce(enc_key, &plaintext, &aad)?;

    Ok(PrivateKeyEncData {
        nonce: encode_base64url_nopad(nonce.as_bytes()),
        ct: encode_base64url_nopad(ct.as_bytes()),
    })
}

pub(super) fn decode_ciphertext_params(
    private_key: &PrivateKey,
) -> Result<PrivateKeyCiphertextParams> {
    let nonce_bytes: [u8; 24] =
        decode_base64url_nopad_array(&private_key.encrypted.nonce, "nonce")?;
    let nonce = XChaChaNonce::new(nonce_bytes);
    let ct = decode_base64url_nopad_ciphertext(&private_key.encrypted.ct, "ct")?;
    let aad = build_private_key_aad(&private_key.protected)?;
    Ok(PrivateKeyCiphertextParams { nonce, ct, aad })
}

pub(super) fn decrypt_private_key_plaintext(
    enc_key: &XChaChaKey,
    params: &PrivateKeyCiphertextParams,
    kid: &str,
    debug_enabled: bool,
    caller: &str,
) -> Result<PrivateKeyPlaintext> {
    if debug_enabled {
        debug!(
            "[CRYPTO] XChaCha20-Poly1305: {}: decrypt (kid: {})",
            caller,
            format_kid_half_display_lossy(kid)
        );
    }
    let plaintext_json = xchacha::decrypt(enc_key, &params.nonce, &params.aad, &params.ct)?;

    serde_json::from_slice(plaintext_json.as_bytes())
        .map_err(|_| Error::build_crypto_error("Failed to deserialize plaintext".to_string()))
}
