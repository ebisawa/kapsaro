// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Read/query operations for kv-enc documents.

use super::decrypt::decrypt_kv_document_with_context;
use crate::feature::context::crypto::CryptoContext;
use crate::feature::verify::kv::signature::verify_kv_content;
use crate::format::content::KvEncContent;
use crate::support::secret::SecretString;
use crate::{Error, Result};
use std::collections::{BTreeMap, HashMap};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvDisclosedEntry {
    pub key: String,
    pub disclosed: bool,
}

/// List all KV keys with their disclosed status.
pub fn list_kv_keys_with_disclosed(content: &KvEncContent) -> Result<Vec<KvDisclosedEntry>> {
    let doc = content.parse()?;
    let mut keys: Vec<KvDisclosedEntry> = doc
        .entries()
        .iter()
        .map(|entry| KvDisclosedEntry {
            key: entry.key().to_string(),
            disclosed: entry.value().disclosed,
        })
        .collect();
    keys.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(keys)
}

/// Decrypt all KV entries and return as a HashMap.
pub fn decrypt_all_kv_values(
    content: &KvEncContent,
    member_handle: &str,
    key_ctx: &CryptoContext,
    verbose: bool,
) -> Result<HashMap<String, SecretString>> {
    let verified_doc = verify_kv_content(content, verbose)?;
    let kv_map =
        decrypt_kv_document_with_context(&verified_doc, member_handle, key_ctx, verbose)?.value;
    Ok(decode_decrypted_kv_values(kv_map)?.into_iter().collect())
}

pub(crate) fn decode_decrypted_kv_values<I>(kv_map: I) -> Result<BTreeMap<String, SecretString>>
where
    I: IntoIterator<Item = (String, Zeroizing<Vec<u8>>)>,
{
    kv_map
        .into_iter()
        .map(|(key, value)| decode_decrypted_kv_value(&key, value).map(|value| (key, value)))
        .collect()
}

pub(crate) fn decode_decrypted_kv_value(
    key: &str,
    value: Zeroizing<Vec<u8>>,
) -> Result<SecretString> {
    SecretString::try_from(value).map_err(|e| {
        Error::build_parse_error_with_source(
            format!("Invalid UTF-8 in decrypted value for '{}': {}", key, e),
            e,
        )
    })
}
