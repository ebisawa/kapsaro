// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Entry Encryption/Decryption for kv-enc

use crate::crypto::aead::xchacha::{
    decrypt as xchacha_decrypt, encrypt_with_fresh_nonce as xchacha_encrypt_with_fresh_nonce,
};
use crate::crypto::types::data::Plaintext;
use crate::crypto::types::keys::XChaChaKey;
use crate::crypto::types::primitives::{FreshXChaChaNonce, XChaChaNonce};
use crate::feature::envelope::binding::build_kv_entry_aad;
use crate::feature::envelope::key_schedule::KvKeySchedule;
use crate::format::codec::base64_public::{
    decode_base64url_nopad_array, decode_base64url_nopad_ciphertext, encode_base64url_nopad,
};
use crate::model::kv_enc::entry::KvEntryValue;
use crate::model::wire::algorithm;
use crate::Result;
use tracing::debug;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Encrypt a single KV entry
pub(crate) fn encrypt_entry(
    key: &str,
    value: &str,
    key_schedule: &KvKeySchedule,
    sid: &Uuid,
    debug: bool,
    caller: &str,
    disclosed: bool,
) -> Result<KvEntryValue> {
    let fresh_nonce = FreshXChaChaNonce::generate()?;
    let nonce_b64 = encode_base64url_nopad(fresh_nonce.as_bytes());
    let cek = key_schedule.derive_cek(key, &nonce_b64)?;
    let cek_key = XChaChaKey::from_slice(cek.as_bytes())?;
    let aad = build_kv_entry_aad(sid, key)?;
    let plaintext = Plaintext::from(value.as_bytes());

    if debug {
        debug!(
            "[CRYPTO] XChaCha20-Poly1305: {}: encrypt (key: cek)",
            caller
        );
    }
    let (ciphertext, _) =
        xchacha_encrypt_with_fresh_nonce(&cek_key, &plaintext, &aad, fresh_nonce)?;

    Ok(KvEntryValue {
        nonce: nonce_b64,
        ct: encode_base64url_nopad(ciphertext.as_bytes()),
        disclosed,
    })
}

/// Decrypt a single KV entry
///
/// Returns plaintext wrapped in Zeroizing<Vec<u8>> to ensure it's zeroed when dropped.
/// Callers should convert to String only when necessary (e.g., for display/output).
pub(crate) fn decrypt_entry(
    entry: &KvEntryValue,
    key: &str,
    aead: &str,
    key_schedule: &KvKeySchedule,
    sid: &Uuid,
    debug: bool,
    caller: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    validate_kv_entry_aead(aead)?;
    let cek = key_schedule.derive_cek(key, &entry.nonce)?;
    let cek_key = XChaChaKey::from_slice(cek.as_bytes())?;
    let nonce_bytes: [u8; 24] = decode_base64url_nopad_array(&entry.nonce, "nonce")?;
    let nonce = XChaChaNonce::new(nonce_bytes);
    let ciphertext = decode_base64url_nopad_ciphertext(&entry.ct, "ct")?;
    let aad = build_kv_entry_aad(sid, key)?;

    if debug {
        debug!(
            "[CRYPTO] XChaCha20-Poly1305: {}: decrypt (key: cek)",
            caller
        );
    }
    let mut plaintext = xchacha_decrypt(&cek_key, &nonce, &aad, &ciphertext)?;
    Ok(plaintext.take_zeroizing_vec())
}

fn validate_kv_entry_aead(aead: &str) -> Result<()> {
    if aead != algorithm::AEAD_XCHACHA20_POLY1305 {
        return Err(crate::Error::build_crypto_error(format!(
            "Unsupported AEAD algorithm: {}",
            aead
        )));
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_envelope_entry_test.rs"]
mod tests;
