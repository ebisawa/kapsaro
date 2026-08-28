// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File payload decryption operations

use crate::crypto::aead::xchacha::decrypt as xchacha_decrypt;
use crate::crypto::types::keys::XChaChaKey;
use crate::crypto::types::primitives::XChaChaNonce;
use crate::feature::context::crypto::{CryptoContext, DecryptionResult};
use crate::feature::envelope::binding::build_file_payload_aad;
use crate::feature::envelope::key_possession::verify_file_key_possession;
use crate::feature::envelope::unwrap::unwrap_master_key_for_file_with_context;
use crate::format::codec::base64_public::{
    decode_base64url_nopad_array, decode_base64url_nopad_ciphertext,
};
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::model::wire::{algorithm, format};
use crate::{Error, Result};
use tracing::debug;
use zeroize::Zeroizing;

/// Validate file-enc v7 format structure.
fn validate_file_enc_document_format(verified_doc: &VerifiedFileEncDocument) -> Result<()> {
    let doc = verified_doc.document();
    if doc.protected.format != format::FILE_ENC_V1 {
        return Err(Error::build_parse_error(format!(
            "Invalid format: expected '{}', got '{}'",
            format::FILE_ENC_V1,
            doc.protected.format
        )));
    }

    Ok(())
}

/// Validate file-enc v7 payload structure and algorithm.
fn validate_file_enc_document_payload(verified_doc: &VerifiedFileEncDocument) -> Result<()> {
    let doc = verified_doc.document();
    if doc.protected.payload.protected.format != format::FILE_PAYLOAD_V1 {
        return Err(Error::build_parse_error(format!(
            "Invalid payload format: expected '{}', got '{}'",
            format::FILE_PAYLOAD_V1,
            doc.protected.payload.protected.format
        )));
    }

    if doc.protected.payload.protected.alg.aead != algorithm::AEAD_XCHACHA20_POLY1305 {
        return Err(Error::build_crypto_error(format!(
            "Unsupported AEAD algorithm: {}",
            doc.protected.payload.protected.alg.aead
        )));
    }

    Ok(())
}

/// Decrypt file-enc v7 payload content.
pub(crate) fn decrypt_file_payload(
    verified_doc: &VerifiedFileEncDocument,
    content_key: &XChaChaKey,
    caller: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let doc = verified_doc.document();
    debug!(
        "[CRYPTO] XChaCha20-Poly1305: {}: decrypt (key: dek)",
        caller
    );
    // Build AAD from payload.protected (JCS normalized)
    let aad = build_file_payload_aad(&doc.protected.payload.protected)?;

    // Decode nonce and ciphertext
    let nonce_bytes: [u8; 24] =
        decode_base64url_nopad_array(&doc.protected.payload.encrypted.nonce, "nonce")?;
    let nonce = XChaChaNonce::new(nonce_bytes);
    let ciphertext = decode_base64url_nopad_ciphertext(&doc.protected.payload.encrypted.ct, "ct")?;

    // Decrypt payload
    let mut plaintext = xchacha_decrypt(content_key, &nonce, &aad, &ciphertext)?;
    Ok(plaintext.take_zeroizing_vec())
}

/// Decrypt file-enc v7 format with the local key the crypto context selects.
///
/// This function requires a VerifiedFileEncDocument, ensuring that signature
/// verification has occurred before decryption. This is enforced by the type system.
///
/// # Arguments
/// * `verified_doc` - Verified FileEncDocument structure (signature must be verified)
/// * `member_handle` - Resolved member handle used to find the wrap
/// * `key_ctx` - Crypto context that selects the local key to unwrap with
///
/// # Returns
/// Decrypted content wrapped in Zeroizing to ensure it's zeroed when dropped,
/// alongside the key the unwrap step ended up using
pub fn decrypt_file_document_with_context(
    verified_doc: &VerifiedFileEncDocument,
    member_handle: &str,
    key_ctx: &CryptoContext,
) -> Result<DecryptionResult<Zeroizing<Vec<u8>>>> {
    validate_file_enc_document_format(verified_doc)?;
    validate_file_enc_document_payload(verified_doc)?;

    let doc = verified_doc.document();
    if doc.protected.payload.protected.sid != doc.protected.sid {
        return Err(Error::build_crypto_error(format!(
            "SID mismatch: payload.protected.sid ({}) != protected.sid ({})",
            doc.protected.payload.protected.sid, doc.protected.sid
        )));
    }

    let content_key =
        unwrap_master_key_for_file_with_context(verified_doc, member_handle, key_ctx)?;
    let key_info = content_key.key_info;
    let possession = verify_file_key_possession(verified_doc, content_key.value)?;
    let plaintext = decrypt_file_payload(
        possession.document(),
        possession.content_key(),
        "decrypt_file_document_with_context",
    )?;
    Ok(DecryptionResult {
        value: plaintext,
        key_info,
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_decrypt_test.rs"]
mod feature_decrypt_test;
