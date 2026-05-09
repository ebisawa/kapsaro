// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV decryption operations

use crate::crypto::types::keys::MasterKey;
use crate::feature::context::crypto::{CryptoContext, DecryptionResult};
use crate::feature::envelope::entry::decrypt_entry;
use crate::feature::envelope::unwrap::{
    unwrap_master_key_for_kv, unwrap_master_key_for_kv_with_context,
};
use crate::model::kv_enc::document::KvEncEntry;
use crate::model::kv_enc::verified::VerifiedKvEncDocument;
use crate::model::verified::VerifiedPrivateKey;
use crate::Result;
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Decrypt all KV entries from parsed lines.
///
/// # Arguments
/// * `entries` - Parsed KvEncLine entries (filtered to KV lines)
/// * `master_key` - Master key for decryption
/// * `sid` - Session ID from HEAD
/// * `debug` - Enable debug logging
///
/// # Returns
/// Decrypted key-value map with values wrapped in Zeroizing<Vec<u8>>
pub(crate) fn decrypt_kv_entries(
    entries: &[KvEncEntry],
    master_key: &MasterKey,
    sid: &Uuid,
    aead: &str,
    debug: bool,
) -> Result<HashMap<String, Zeroizing<Vec<u8>>>> {
    let mut kv_map = HashMap::new();
    for entry in entries {
        let value = decrypt_entry(
            entry.value(),
            entry.key(),
            aead,
            master_key,
            sid,
            debug,
            "decrypt_kv_entries",
        )?;
        kv_map.insert(entry.key().to_string(), value);
    }
    Ok(kv_map)
}

/// Decrypt a single KV entry by key name from a verified kv-enc document.
pub fn decrypt_kv_single_entry(
    verified_doc: &VerifiedKvEncDocument,
    member_handle: &str,
    kid: &str,
    private_key: &VerifiedPrivateKey,
    key: &str,
    debug: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    let doc = verified_doc.document();
    let sid = doc.head().sid;

    let master_key = unwrap_master_key_for_kv(
        &sid,
        &doc.wrap().wrap,
        member_handle,
        kid,
        private_key,
        debug,
    )?;

    let entry = doc
        .entry(key)
        .ok_or_else(|| crate::Error::InvalidOperation {
            message: format!("Key '{}' not found", key),
        })?;
    decrypt_entry(
        entry.value(),
        entry.key(),
        &doc.head().alg.aead,
        &master_key,
        &sid,
        debug,
        "decrypt_kv_single_entry",
    )
}

pub fn decrypt_kv_single_entry_with_context(
    verified_doc: &VerifiedKvEncDocument,
    member_handle: &str,
    key_ctx: &CryptoContext,
    key: &str,
    debug: bool,
) -> Result<DecryptionResult<Zeroizing<Vec<u8>>>> {
    let doc = verified_doc.document();
    let sid = doc.head().sid;
    let master_key = unwrap_master_key_for_kv_with_context(
        &sid,
        &doc.wrap().wrap,
        member_handle,
        key_ctx,
        debug,
    )?;

    let entry = doc
        .entry(key)
        .ok_or_else(|| crate::Error::InvalidOperation {
            message: format!("Key '{}' not found", key),
        })?;
    let value = decrypt_entry(
        entry.value(),
        entry.key(),
        &doc.head().alg.aead,
        &master_key.value,
        &sid,
        debug,
        "decrypt_kv_single_entry_with_context",
    )?;
    Ok(DecryptionResult {
        value,
        key_info: master_key.key_info,
    })
}

/// Decrypt kv-enc v5 format to KV map
///
/// This function requires a VerifiedKvEncDocument, ensuring that signature
/// verification has occurred before decryption. This is enforced by the type system.
///
/// # Arguments
/// * `verified_doc` - Verified KvEncDocument (signature must be verified)
/// * `member_handle` - Resolved member handle used to find the wrap
/// * `kid` - Key ID to find the wrap item
/// * `private_key` - PrivateKeyPlaintext containing the KEM private key
/// * `debug` - Enable debug logging
///
/// # Returns
/// Decrypted key-value map with values wrapped in Zeroizing<Vec<u8>>
pub fn decrypt_kv_document(
    verified_doc: &VerifiedKvEncDocument,
    member_handle: &str,
    kid: &str,
    private_key: &VerifiedPrivateKey,
    debug: bool,
) -> Result<HashMap<String, Zeroizing<Vec<u8>>>> {
    let doc = verified_doc.document();
    let sid = doc.head().sid;

    let master_key = unwrap_master_key_for_kv(
        &sid,
        &doc.wrap().wrap,
        member_handle,
        kid,
        private_key,
        debug,
    )?;

    decrypt_kv_entries(
        doc.entries(),
        &master_key,
        &sid,
        &doc.head().alg.aead,
        debug,
    )
}

pub fn decrypt_kv_document_with_context(
    verified_doc: &VerifiedKvEncDocument,
    member_handle: &str,
    key_ctx: &CryptoContext,
    debug: bool,
) -> Result<DecryptionResult<HashMap<String, Zeroizing<Vec<u8>>>>> {
    let doc = verified_doc.document();
    let sid = doc.head().sid;
    let master_key = unwrap_master_key_for_kv_with_context(
        &sid,
        &doc.wrap().wrap,
        member_handle,
        key_ctx,
        debug,
    )?;
    let kv_map = decrypt_kv_entries(
        doc.entries(),
        &master_key.value,
        &sid,
        &doc.head().alg.aead,
        debug,
    )?;
    Ok(DecryptionResult {
        value: kv_map,
        key_info: master_key.key_info,
    })
}
