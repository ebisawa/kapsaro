// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File payload encryption primitives.

use crate::crypto::aead::xchacha::encrypt_with_nonce as xchacha_encrypt_with_nonce;
use crate::crypto::types::data::Plaintext;
use crate::crypto::types::keys::XChaChaKey;
use crate::feature::envelope::binding::build_file_payload_aad;
use crate::model::file_enc::{FilePayloadCiphertext, FilePayloadHeader};
use crate::support::codec::base64_public::encode_base64url_nopad;
use crate::Result;
use tracing::debug;

/// Encrypt file payload content with XChaCha20-Poly1305.
///
/// Constructs AAD from `payload_header`, encrypts `plaintext` and returns
/// `FilePayloadCiphertext` with base64url-encoded nonce and ciphertext.
pub(crate) fn encrypt_file_payload_content(
    plaintext: &Plaintext,
    key: &XChaChaKey,
    payload_header: &FilePayloadHeader,
    debug: bool,
    caller: &str,
) -> Result<FilePayloadCiphertext> {
    if debug {
        debug!(
            "[CRYPTO] XChaCha20-Poly1305: {}: encrypt (key: dek)",
            caller
        );
    }
    let aad = build_file_payload_aad(payload_header)?;
    let (ciphertext, nonce) = xchacha_encrypt_with_nonce(key, plaintext, &aad)?;
    Ok(FilePayloadCiphertext {
        nonce: encode_base64url_nopad(nonce.as_bytes()),
        ct: encode_base64url_nopad(ciphertext.as_bytes()),
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/feature_envelope_payload_test.rs"]
mod tests;
