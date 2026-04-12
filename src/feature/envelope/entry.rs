// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Entry Encryption/Decryption for kv-enc

use crate::crypto::aead::xchacha::{
    decrypt as xchacha_decrypt, encrypt_with_nonce as xchacha_encrypt_with_nonce,
};
use crate::crypto::types::data::Plaintext;
use crate::crypto::types::keys::{MasterKey, XChaChaKey};
use crate::crypto::types::primitives::XChaChaNonce;
use crate::feature::envelope::binding::build_kv_entry_aad;
use crate::model::identifiers::alg;
use crate::model::kv_enc::entry::KvEntryValue;
use crate::support::codec::base64_public::{
    decode_base64url_nopad_array, decode_base64url_nopad_ciphertext, encode_base64url_nopad,
};
use crate::Result;
use tracing::debug;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::cek::{derive_cek, generate_salt};

/// Encrypt a single KV entry
pub(crate) fn encrypt_entry(
    key: &str,
    value: &str,
    master_key: &MasterKey,
    sid: &Uuid,
    debug: bool,
    caller: &str,
    disclosed: bool,
) -> Result<KvEntryValue> {
    // Generate 32 bytes random salt and encode as base64url (no padding)
    let salt = generate_salt();

    let cek = derive_cek(master_key, &salt, sid, debug)?;
    let cek_key = XChaChaKey::from_slice(cek.as_bytes())?;
    let aad = build_kv_entry_aad(sid, key)?;
    let plaintext = Plaintext::from(value.as_bytes());

    if debug {
        debug!(
            "[CRYPTO] XChaCha20-Poly1305: {}: encrypt (key: cek)",
            caller
        );
    }
    let (ciphertext, nonce) = xchacha_encrypt_with_nonce(&cek_key, &plaintext, &aad)?;

    Ok(KvEntryValue {
        salt,
        k: key.to_string(),
        aead: alg::AEAD_XCHACHA20_POLY1305.to_string(),
        nonce: encode_base64url_nopad(nonce.as_bytes()),
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
    master_key: &MasterKey,
    sid: &Uuid,
    debug: bool,
    caller: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let cek = derive_cek(master_key, &entry.salt, sid, debug)?;
    let cek_key = XChaChaKey::from_slice(cek.as_bytes())?;
    let nonce_bytes: [u8; 24] = decode_base64url_nopad_array(&entry.nonce, "nonce")?;
    let nonce = XChaChaNonce::new(nonce_bytes);
    let ciphertext = decode_base64url_nopad_ciphertext(&entry.ct, "ct")?;
    let aad = build_kv_entry_aad(sid, &entry.k)?;

    if debug {
        debug!(
            "[CRYPTO] XChaCha20-Poly1305: {}: decrypt (key: cek)",
            caller
        );
    }
    let plaintext = xchacha_decrypt(&cek_key, &nonce, &aad, &ciphertext)?;

    // Convert Zeroizing<Plaintext> to Zeroizing<Vec<u8>>
    Ok(plaintext.to_zeroizing_vec())
}
