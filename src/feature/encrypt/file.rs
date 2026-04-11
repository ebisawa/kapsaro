// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File payload encryption operations

use crate::crypto::types::data::Plaintext;
use crate::crypto::types::keys::{MasterKey, XChaChaKey};
use crate::feature::envelope::payload::encrypt_file_payload_content;
use crate::feature::envelope::signature::{sign_file_document, SigningContext};
use crate::feature::envelope::wrap::{build_wraps_for_recipients, WrapFormat};
use crate::model::common::WrapItem;
use crate::model::file_enc::{
    FileEncAlgorithm, FileEncDocument, FileEncDocumentProtected, FilePayload,
    FilePayloadCiphertext, FilePayloadHeader,
};
use crate::model::identifiers::{alg, format};
use crate::model::public_key::VerifiedRecipientKey;
use crate::support::time::current_timestamp;
use crate::Result;
use rand::rngs::OsRng;
use rand::RngCore;
use uuid::Uuid;
use zeroize::Zeroizing;

fn validate_recipient_members(
    recipient_ids: &[String],
    members: &[VerifiedRecipientKey],
) -> Result<()> {
    if recipient_ids.len() != members.len() {
        return Err(crate::Error::InvalidArgument {
            message: format!(
                "Recipients count ({}) does not match public keys ({})",
                recipient_ids.len(),
                members.len()
            ),
        });
    }

    for (recipient_id, member) in recipient_ids.iter().zip(members.iter()) {
        let member_id = &member.document().protected.member_id;
        if recipient_id != member_id {
            return Err(crate::Error::InvalidArgument {
                message: format!(
                    "Recipient '{}' does not match member '{}'",
                    recipient_id, member_id
                ),
            });
        }
    }

    Ok(())
}

/// Build encryption context: generate content key, create XChaChaKey
///
/// Returns plaintext wrapped in Zeroizing to ensure it's zeroed after encryption.
fn build_encrypt_context(content: &[u8]) -> Result<(MasterKey, Zeroizing<Vec<u8>>, XChaChaKey)> {
    // Generate content key (32 bytes random)
    let mut content_key_bytes = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(content_key_bytes.as_mut());
    let content_key = MasterKey::from_zeroizing(content_key_bytes);
    let xchacha_key = XChaChaKey::from_slice(content_key.as_bytes())?;

    // Wrap plaintext in Zeroizing to ensure it's zeroed after use
    Ok((content_key, Zeroizing::new(content.to_vec()), xchacha_key))
}

/// Encrypt payload with XChaCha20-Poly1305
///
/// Takes Zeroizing<Vec<u8>> to ensure plaintext is zeroed after encryption.
fn encrypt_payload(
    plaintext: &Zeroizing<Vec<u8>>,
    key: &XChaChaKey,
    sid: &Uuid,
    debug: bool,
    caller: &str,
) -> Result<(FilePayloadHeader, FilePayloadCiphertext)> {
    let payload_protected = FilePayloadHeader {
        format: format::FILE_PAYLOAD_V3.to_string(),
        sid: *sid,
        alg: FileEncAlgorithm {
            aead: alg::AEAD_XCHACHA20_POLY1305.to_string(),
        },
    };

    let plaintext_obj = Plaintext::from(plaintext.as_slice());
    let encrypted =
        encrypt_file_payload_content(&plaintext_obj, key, &payload_protected, debug, caller)?;

    Ok((payload_protected, encrypted))
}

/// Create wrap items for recipients from verified members.
///
/// # Arguments
/// * `members` - Verified public keys with attested identity
/// * `sid` - Session ID (UUID)
/// * `content_key` - Master key to wrap
fn build_recipient_wraps(
    members: &[VerifiedRecipientKey],
    sid: &Uuid,
    content_key: &MasterKey,
    debug: bool,
) -> Result<Vec<WrapItem>> {
    build_wraps_for_recipients(members, sid, content_key, WrapFormat::File, debug)
}

/// Build FileEncDocumentProtected structure
fn build_file_enc_document_protected(
    sid: Uuid,
    wrap: Vec<WrapItem>,
    payload: FilePayload,
    timestamp: String,
) -> FileEncDocumentProtected {
    FileEncDocumentProtected {
        format: format::FILE_ENC_V3.to_string(),
        sid,
        wrap,
        removed_recipients: None,
        payload,
        created_at: timestamp.clone(),
        updated_at: timestamp,
    }
}

/// Encrypt file content to file-enc v3 format
///
/// # Arguments
/// * `content` - File content bytes to encrypt
/// * `recipient_ids` - Normalized list of recipient member IDs (order must match members)
/// * `members` - Verified public keys with attested identity
/// * `signing` - Signing context (signing_key, signer_kid, signer_pub, debug)
///
/// # Returns
/// FileEncDocument structure
pub fn encrypt_file_document(
    content: &[u8],
    recipient_ids: &[String],
    members: &[VerifiedRecipientKey],
    signing: &SigningContext<'_>,
) -> Result<FileEncDocument> {
    validate_recipient_members(recipient_ids, members)?;
    let sid = Uuid::new_v4();
    let timestamp = current_timestamp()?;
    let (content_key, payload) =
        encrypt_content_into_payload(content, &sid, signing.debug, "encrypt_file_document")?;
    let protected = assemble_file_enc_protected(
        sid,
        &content_key,
        members,
        payload,
        timestamp,
        signing.debug,
    )?;
    sign_and_finalize_file_document(protected, signing)
}

/// Build encryption context and produce a ready `FilePayload`.
///
/// The plaintext is held inside a `Zeroizing` buffer and zeroed before this
/// helper returns.
fn encrypt_content_into_payload(
    content: &[u8],
    sid: &Uuid,
    debug: bool,
    caller: &str,
) -> Result<(MasterKey, FilePayload)> {
    let (content_key, bytes_to_encrypt, xchacha_key) = build_encrypt_context(content)?;
    let (payload_protected, payload_encrypted) =
        encrypt_payload(&bytes_to_encrypt, &xchacha_key, sid, debug, caller)?;
    Ok((
        content_key,
        FilePayload {
            protected: payload_protected,
            encrypted: payload_encrypted,
        },
    ))
}

/// Wrap the content key for each recipient and assemble the protected header.
fn assemble_file_enc_protected(
    sid: Uuid,
    content_key: &MasterKey,
    members: &[VerifiedRecipientKey],
    payload: FilePayload,
    timestamp: String,
    debug: bool,
) -> Result<FileEncDocumentProtected> {
    let wrap = build_recipient_wraps(members, &sid, content_key, debug)?;
    Ok(build_file_enc_document_protected(
        sid, wrap, payload, timestamp,
    ))
}

/// Sign the protected header and produce the final `FileEncDocument`.
fn sign_and_finalize_file_document(
    protected: FileEncDocumentProtected,
    signing: &SigningContext<'_>,
) -> Result<FileEncDocument> {
    let signature = sign_file_document(
        &protected,
        signing.signing_key,
        signing.signer_kid,
        signing.signer_pub.clone(),
        signing.debug,
    )?;
    Ok(FileEncDocument {
        protected,
        signature,
    })
}
