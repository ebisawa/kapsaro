// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Token encoding for KV entries.
//! Encrypts each entry under its own derived key and renders it as one token.

use std::collections::HashMap;

use uuid::Uuid;

use crate::crypto::types::keys::MasterKey;
use crate::feature::envelope::entry::encrypt_entry;
use crate::feature::envelope::key_schedule::KvKeySchedule;
use crate::format::token::TokenCodec;
use crate::model::kv_enc::entry::KvEntryValue;
use crate::Result;

use super::types::KvInputEntry;

/// Encode encrypted KV entries to token strings.
pub(crate) fn encode_kv_entries_to_tokens(
    entries: &[(String, KvEntryValue)],
    token_codec: TokenCodec,
) -> Result<Vec<(String, String)>> {
    entries
        .iter()
        .map(|(key, entry)| {
            let token = TokenCodec::encode(token_codec, entry)?;
            Ok((key.clone(), token))
        })
        .collect()
}

/// Detect the token codec a document is encoded with.
///
/// Takes the `:WRAP` token rather than the line list so the caller cannot
/// supply input that has no codec to detect.
pub(crate) fn detect_token_codec(
    wrap_token: &str,
    override_codec: Option<TokenCodec>,
) -> TokenCodec {
    override_codec.unwrap_or_else(|| TokenCodec::detect(wrap_token))
}

pub(crate) fn build_entry_tokens<'a>(
    entries: &'a [KvInputEntry],
    master_key: &MasterKey,
    sid: &Uuid,
    codec: TokenCodec,
) -> Result<HashMap<&'a str, String>> {
    let key_schedule = KvKeySchedule::extract(master_key, sid)?;
    entries
        .iter()
        .map(|entry| {
            let token = encode_encrypted_entry(
                &entry.key,
                entry.value.as_str(),
                &key_schedule,
                sid,
                codec,
            )?;
            Ok((entry.key.as_str(), token))
        })
        .collect()
}

fn encode_encrypted_entry(
    key: &str,
    value: &str,
    key_schedule: &KvKeySchedule,
    sid: &Uuid,
    codec: TokenCodec,
) -> Result<String> {
    let new_entry = encrypt_entry(
        key,
        value,
        key_schedule,
        sid,
        "encode_encrypted_entry",
        false,
    )?;
    TokenCodec::encode(codec, &new_entry)
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_kv_entry_codec_test.rs"]
mod tests;
