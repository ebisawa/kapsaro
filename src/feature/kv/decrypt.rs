// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV decryption operations

use crate::crypto::types::keys::MasterKey;
use crate::feature::context::crypto::{CryptoContext, DecryptionResult};
use crate::feature::envelope::entry::decrypt_entry;
use crate::feature::envelope::unwrap::{
    unwrap_master_key_for_kv, unwrap_master_key_for_kv_with_context,
};
use crate::format::kv::enc::canonical::extract_kv_header_tokens;
use crate::format::kv::enc::parser::KvEncParser;
use crate::format::schema::document::{
    parse_kv_entry_token, parse_kv_head_token, parse_kv_wrap_token,
};
use crate::model::kv_enc::header::{KvHeader, KvWrap};
use crate::model::kv_enc::line::KvEncLine;
use crate::model::kv_enc::verified::VerifiedKvEncDocument;
use crate::model::verified::VerifiedPrivateKey;
use crate::Result;
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Parse kv-enc v4 content and extract HEAD, WRAP, and lines.
///
/// # Arguments
/// * `content` - kv-enc v4 format content string
/// * `debug` - Enable debug logging
///
/// # Returns
/// Tuple of (HEAD data, WRAP data, all parsed lines)
pub(crate) fn parse_kv_enc_content(
    content: &str,
    debug: bool,
) -> Result<(KvHeader, KvWrap, Vec<KvEncLine>)> {
    let parser = KvEncParser::new(content);
    let lines = parser.parse_all()?;

    // Extract and parse HEAD and WRAP
    let (head_token, wrap_token) = extract_kv_header_tokens(&lines)?;

    let _ = debug;
    let head_data: KvHeader = parse_kv_head_token(&head_token)?;
    let wrap_data: KvWrap = parse_kv_wrap_token(&wrap_token)?;

    Ok((head_data, wrap_data, lines))
}

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
    entries: &[KvEncLine],
    master_key: &MasterKey,
    sid: &Uuid,
    debug: bool,
) -> Result<HashMap<String, Zeroizing<Vec<u8>>>> {
    let mut kv_map = HashMap::new();
    for line in entries {
        if let KvEncLine::KV { key, token } = line {
            let _ = debug;
            let entry = parse_kv_entry_token(token)?;
            let value = decrypt_entry(&entry, master_key, sid, debug, "decrypt_kv_entries")?;
            kv_map.insert(key.clone(), value);
        }
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
    let (head_data, wrap_data, lines) = parse_kv_enc_content(doc.content(), debug)?;
    let sid = head_data.sid;

    let master_key = unwrap_master_key_for_kv(
        &sid,
        &wrap_data.wrap,
        member_handle,
        kid,
        private_key,
        debug,
    )?;

    // Find the specific KV line by key name
    let kv_line = lines
        .iter()
        .find(|l| matches!(l, KvEncLine::KV { key: k, .. } if k == key))
        .ok_or_else(|| crate::Error::InvalidOperation {
            message: format!("Key '{}' not found", key),
        })?;

    if let KvEncLine::KV { key: k, token } = kv_line {
        let _ = (debug, k);
        let entry = parse_kv_entry_token(token)?;
        decrypt_entry(&entry, &master_key, &sid, debug, "decrypt_kv_single_entry")
    } else {
        unreachable!()
    }
}

pub fn decrypt_kv_single_entry_with_context(
    verified_doc: &VerifiedKvEncDocument,
    member_handle: &str,
    key_ctx: &CryptoContext,
    key: &str,
    debug: bool,
) -> Result<DecryptionResult<Zeroizing<Vec<u8>>>> {
    let doc = verified_doc.document();
    let (head_data, wrap_data, lines) = parse_kv_enc_content(doc.content(), debug)?;
    let sid = head_data.sid;
    let master_key = unwrap_master_key_for_kv_with_context(
        &sid,
        &wrap_data.wrap,
        member_handle,
        key_ctx,
        debug,
    )?;

    let kv_line = lines
        .iter()
        .find(|l| matches!(l, KvEncLine::KV { key: k, .. } if k == key))
        .ok_or_else(|| crate::Error::InvalidOperation {
            message: format!("Key '{}' not found", key),
        })?;

    if let KvEncLine::KV { token, .. } = kv_line {
        let entry = parse_kv_entry_token(token)?;
        let value = decrypt_entry(
            &entry,
            &master_key.value,
            &sid,
            debug,
            "decrypt_kv_single_entry_with_context",
        )?;
        Ok(DecryptionResult {
            value,
            key_info: master_key.key_info,
        })
    } else {
        unreachable!()
    }
}

/// Decrypt kv-enc v4 format to KV map
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
    let (head_data, wrap_data, lines) = parse_kv_enc_content(doc.content(), debug)?;
    let sid = head_data.sid;

    let master_key = unwrap_master_key_for_kv(
        &sid,
        &wrap_data.wrap,
        member_handle,
        kid,
        private_key,
        debug,
    )?;

    decrypt_kv_entries(&lines, &master_key, &sid, debug)
}

pub fn decrypt_kv_document_with_context(
    verified_doc: &VerifiedKvEncDocument,
    member_handle: &str,
    key_ctx: &CryptoContext,
    debug: bool,
) -> Result<DecryptionResult<HashMap<String, Zeroizing<Vec<u8>>>>> {
    let doc = verified_doc.document();
    let (head_data, wrap_data, lines) = parse_kv_enc_content(doc.content(), debug)?;
    let sid = head_data.sid;
    let master_key = unwrap_master_key_for_kv_with_context(
        &sid,
        &wrap_data.wrap,
        member_handle,
        key_ctx,
        debug,
    )?;
    let kv_map = decrypt_kv_entries(&lines, &master_key.value, &sid, debug)?;
    Ok(DecryptionResult {
        value: kv_map,
        key_info: master_key.key_info,
    })
}
