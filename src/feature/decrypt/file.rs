// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File payload decryption operations

use crate::crypto::aead::xchacha::decrypt as xchacha_decrypt;
use crate::crypto::types::keys::{MasterKey, XChaChaKey};
use crate::crypto::types::primitives::XChaChaNonce;
use crate::feature::context::crypto::{CryptoContext, DecryptionResult};
use crate::feature::envelope::binding::build_file_payload_aad;
use crate::feature::envelope::unwrap::{
    unwrap_master_key_for_file, unwrap_master_key_for_file_with_context,
};
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::model::identifiers::{alg, format};
use crate::model::verified::VerifiedPrivateKey;
use crate::support::codec::base64_public::{
    decode_base64url_nopad_array, decode_base64url_nopad_ciphertext,
};
use crate::{Error, Result};
use tracing::debug;
use zeroize::Zeroizing;

/// Validate file-enc v4 format structure.
fn validate_file_enc_document_format(verified_doc: &VerifiedFileEncDocument) -> Result<()> {
    let doc = verified_doc.document();
    if doc.protected.format != format::FILE_ENC_V4 {
        return Err(Error::Parse {
            message: format!(
                "Invalid format: expected '{}', got '{}'",
                format::FILE_ENC_V4,
                doc.protected.format
            ),
            source: None,
        });
    }

    Ok(())
}

/// Validate file-enc v4 payload structure and algorithm.
fn validate_file_enc_document_payload(verified_doc: &VerifiedFileEncDocument) -> Result<()> {
    let doc = verified_doc.document();
    if doc.protected.payload.protected.format != format::FILE_PAYLOAD_V4 {
        return Err(Error::Parse {
            message: format!(
                "Invalid payload format: expected '{}', got '{}'",
                format::FILE_PAYLOAD_V4,
                doc.protected.payload.protected.format
            ),
            source: None,
        });
    }

    if doc.protected.payload.protected.alg.aead != alg::AEAD_XCHACHA20_POLY1305 {
        return Err(Error::Crypto {
            message: format!(
                "Unsupported AEAD algorithm: {}",
                doc.protected.payload.protected.alg.aead
            ),
            source: None,
        });
    }

    Ok(())
}

/// Decrypt file-enc v4 payload content.
pub(crate) fn decrypt_file_payload(
    verified_doc: &VerifiedFileEncDocument,
    content_key: &MasterKey,
    debug: bool,
    caller: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let doc = verified_doc.document();
    if debug {
        debug!(
            "[CRYPTO] XChaCha20-Poly1305: {}: decrypt (key: dek)",
            caller
        );
    }
    // Build AAD from payload.protected (JCS normalized)
    let aad = build_file_payload_aad(&doc.protected.payload.protected)?;

    // Decode nonce and ciphertext
    let nonce_bytes: [u8; 24] =
        decode_base64url_nopad_array(&doc.protected.payload.encrypted.nonce, "nonce")?;
    let nonce = XChaChaNonce::new(nonce_bytes);
    let ciphertext = decode_base64url_nopad_ciphertext(&doc.protected.payload.encrypted.ct, "ct")?;

    // Decrypt payload
    let xchacha_key = XChaChaKey::from_slice(content_key.as_bytes())?;
    let plaintext = xchacha_decrypt(&xchacha_key, &nonce, &aad, &ciphertext)?;

    // Convert Zeroizing<Plaintext> to Zeroizing<Vec<u8>>
    Ok(plaintext.to_zeroizing_vec())
}

/// Decrypt file-enc v4 format (value-based)
///
/// This function requires a VerifiedFileEncDocument, ensuring that signature
/// verification has occurred before decryption. This is enforced by the type system.
///
/// # Arguments
/// * `verified_doc` - Verified FileEncDocument structure (signature must be verified)
/// * `member_handle` - Resolved member handle used to find the wrap
/// * `kid` - Key ID to find the wrap item
/// * `private_key` - PrivateKeyPlaintext containing the KEM private key
/// * `debug` - Enable debug logging
///
/// # Returns
/// Decrypted content wrapped in Zeroizing to ensure it's zeroed when dropped
pub fn decrypt_file_document(
    verified_doc: &VerifiedFileEncDocument,
    member_handle: &str,
    kid: &str,
    private_key: &VerifiedPrivateKey,
    debug: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    validate_file_enc_document_format(verified_doc)?;
    validate_file_enc_document_payload(verified_doc)?;

    let doc = verified_doc.document();
    // Verify that payload.protected.sid matches protected.sid (defence-in-depth)
    if doc.protected.payload.protected.sid != doc.protected.sid {
        return Err(Error::Crypto {
            message: format!(
                "SID mismatch: payload.protected.sid ({}) != protected.sid ({})",
                doc.protected.payload.protected.sid, doc.protected.sid
            ),
            source: None,
        });
    }

    // Unwrap content key using the shared helper
    let content_key =
        unwrap_master_key_for_file(verified_doc, member_handle, kid, private_key, debug)?;

    decrypt_file_payload(verified_doc, &content_key, debug, "decrypt_file_document")
}

pub fn decrypt_file_document_with_context(
    verified_doc: &VerifiedFileEncDocument,
    member_handle: &str,
    key_ctx: &CryptoContext,
    debug: bool,
) -> Result<DecryptionResult<Zeroizing<Vec<u8>>>> {
    validate_file_enc_document_format(verified_doc)?;
    validate_file_enc_document_payload(verified_doc)?;

    let doc = verified_doc.document();
    if doc.protected.payload.protected.sid != doc.protected.sid {
        return Err(Error::Crypto {
            message: format!(
                "SID mismatch: payload.protected.sid ({}) != protected.sid ({})",
                doc.protected.payload.protected.sid, doc.protected.sid
            ),
            source: None,
        });
    }

    let content_key =
        unwrap_master_key_for_file_with_context(verified_doc, member_handle, key_ctx, debug)?;
    let plaintext = decrypt_file_payload(
        verified_doc,
        &content_key.value,
        debug,
        "decrypt_file_document_with_context",
    )?;
    Ok(DecryptionResult {
        value: plaintext,
        key_info: content_key.key_info,
    })
}
