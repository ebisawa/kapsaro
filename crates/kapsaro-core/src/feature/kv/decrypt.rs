// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV decryption operations

use crate::feature::context::crypto::{CryptoContext, DecryptionResult};
use crate::feature::envelope::entry::decrypt_entry;
use crate::feature::envelope::key_possession::verify_kv_key_possession;
use crate::feature::envelope::key_schedule::KvKeySchedule;
use crate::feature::envelope::unwrap::unwrap_master_key_for_kv_with_context;
use crate::feature::kv::error::build_key_not_found_error;
use crate::model::kv_enc::document::KvEncEntry;
use crate::model::kv_enc::verified::VerifiedKvEncDocument;
use crate::Result;
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Decrypt all KV entries from parsed lines.
///
/// # Arguments
/// * `entries` - Parsed KvEncLine entries (filtered to KV lines)
/// * `key_schedule` - Artifact key schedule for CEK derivation
/// * `sid` - Session ID from HEAD
///
/// # Returns
/// Decrypted key-value map with values wrapped in `Zeroizing<Vec<u8>>`
pub(crate) fn decrypt_kv_entries(
    entries: &[KvEncEntry],
    key_schedule: &KvKeySchedule,
    sid: &Uuid,
    aead: &str,
) -> Result<HashMap<String, Zeroizing<Vec<u8>>>> {
    let mut kv_map = HashMap::new();
    for entry in entries {
        let value = decrypt_entry(
            entry.value(),
            entry.key(),
            aead,
            key_schedule,
            sid,
            "decrypt_kv_entries",
        )?;
        kv_map.insert(entry.key().to_string(), value);
    }
    Ok(kv_map)
}

/// Decrypt a single KV entry by key name, with the local key the crypto context selects.
pub fn decrypt_kv_single_entry_with_context(
    verified_doc: &VerifiedKvEncDocument,
    member_handle: &str,
    key_ctx: &CryptoContext,
    key: &str,
) -> Result<DecryptionResult<Zeroizing<Vec<u8>>>> {
    let doc = verified_doc.document();
    let sid = doc.head().sid;
    let master_key =
        unwrap_master_key_for_kv_with_context(&sid, &doc.wrap().wrap, member_handle, key_ctx)?;
    let key_info = master_key.key_info;
    let possession = verify_kv_key_possession(verified_doc, master_key.value)?;

    let entry = doc
        .entry(key)
        .ok_or_else(|| build_key_not_found_error(key))?;
    let value = decrypt_entry(
        entry.value(),
        entry.key(),
        &doc.head().alg.aead,
        possession.key_schedule(),
        &sid,
        "decrypt_kv_single_entry_with_context",
    )?;
    Ok(DecryptionResult { value, key_info })
}

/// Decrypt kv-enc v1 format to a KV map, with the local key the crypto context selects.
///
/// This function requires a VerifiedKvEncDocument, ensuring that signature
/// verification has occurred before decryption. This is enforced by the type system.
///
/// # Arguments
/// * `verified_doc` - Verified KvEncDocument (signature must be verified)
/// * `member_handle` - Resolved member handle used to find the wrap
/// * `key_ctx` - Crypto context that selects the local key to unwrap with
///
/// # Returns
/// Decrypted key-value map with values wrapped in `Zeroizing<Vec<u8>>`,
/// alongside the key the unwrap step ended up using
pub fn decrypt_kv_document_with_context(
    verified_doc: &VerifiedKvEncDocument,
    member_handle: &str,
    key_ctx: &CryptoContext,
) -> Result<DecryptionResult<HashMap<String, Zeroizing<Vec<u8>>>>> {
    let doc = verified_doc.document();
    let sid = doc.head().sid;
    let master_key =
        unwrap_master_key_for_kv_with_context(&sid, &doc.wrap().wrap, member_handle, key_ctx)?;
    let key_info = master_key.key_info;
    let possession = verify_kv_key_possession(verified_doc, master_key.value)?;
    let kv_map = decrypt_kv_entries(
        doc.entries(),
        possession.key_schedule(),
        &sid,
        &doc.head().alg.aead,
    )?;
    Ok(DecryptionResult {
        value: kv_map,
        key_info,
    })
}
