// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Read/query operations for kv-enc documents.

use super::decrypt::decrypt_kv_document_with_context;
use crate::feature::context::crypto::CryptoContext;
use crate::feature::verify::kv::signature::verify_kv_content;
use crate::format::content::KvEncContent;
use crate::format::schema::document::parse_kv_entry_token;
use crate::model::kv_enc::line::KvEncLine;
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
    let mut keys = Vec::new();
    for line in doc.lines() {
        if let KvEncLine::KV { key, token } = line {
            let entry = parse_kv_entry_token(token)?;
            keys.push(KvDisclosedEntry {
                key: key.clone(),
                disclosed: entry.disclosed,
            });
        }
    }
    keys.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(keys)
}

/// Decrypt all KV entries and return as a HashMap.
pub fn decrypt_all_kv_values(
    content: &KvEncContent,
    member_id: &str,
    key_ctx: &CryptoContext,
    verbose: bool,
) -> Result<HashMap<String, SecretString>> {
    let verified_doc = verify_kv_content(content, verbose)?;
    let kv_map =
        decrypt_kv_document_with_context(&verified_doc, member_id, key_ctx, verbose)?.value;
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
    SecretString::try_from(value).map_err(|e| Error::Parse {
        message: format!("Invalid UTF-8 in decrypted value for '{}': {}", key, e),
        source: Some(Box::new(e)),
    })
}
