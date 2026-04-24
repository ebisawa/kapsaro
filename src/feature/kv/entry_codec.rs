// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use uuid::Uuid;

use crate::crypto::types::keys::MasterKey;
use crate::feature::envelope::entry::encrypt_entry;
use crate::format::token::TokenCodec;
use crate::model::kv_enc::entry::KvEntryValue;
use crate::model::kv_enc::line::KvEncLine;
use crate::Result;

use super::types::{KvEncodedEntry, KvInputEntry};

/// Encode encrypted KV entries to token strings.
pub(crate) fn encode_kv_entries_to_tokens(
    entries: &[(String, KvEntryValue)],
    token_codec: TokenCodec,
    debug: bool,
    caller: &'static str,
) -> Result<Vec<KvEncodedEntry>> {
    entries
        .iter()
        .map(|(key, entry)| {
            let token =
                TokenCodec::encode_debug(token_codec, entry, debug, Some(&entry.k), Some(caller))?;
            Ok(KvEncodedEntry {
                key: key.clone(),
                token,
            })
        })
        .collect()
}

/// Detect the token codec for a validated KV document.
///
/// Relies on the invariant that `KvEncDocument` is only constructed via
/// `parse_kv_document`, which requires a `:WRAP` line to be present.
pub(crate) fn detect_token_codec(
    lines: &[KvEncLine],
    override_codec: Option<TokenCodec>,
) -> TokenCodec {
    override_codec.unwrap_or_else(|| {
        lines
            .iter()
            .find_map(|line| match line {
                KvEncLine::Wrap { token } => Some(TokenCodec::detect(token)),
                _ => None,
            })
            .expect("WRAP line must exist in validated KvEncDocument")
    })
}

pub(crate) fn build_entry_tokens<'a>(
    entries: &'a [KvInputEntry],
    master_key: &MasterKey,
    sid: &Uuid,
    codec: TokenCodec,
    verbose: bool,
    caller: &'static str,
) -> Result<HashMap<&'a str, String>> {
    entries
        .iter()
        .map(|entry| {
            let token = encode_encrypted_entry(
                &entry.key,
                &entry.value,
                master_key,
                sid,
                codec,
                verbose,
                caller,
            )?;
            Ok((entry.key.as_str(), token))
        })
        .collect()
}

fn encode_encrypted_entry(
    key: &str,
    value: &str,
    master_key: &MasterKey,
    sid: &Uuid,
    codec: TokenCodec,
    verbose: bool,
    caller: &'static str,
) -> Result<String> {
    let new_entry = encrypt_entry(key, value, master_key, sid, verbose, caller, false)?;
    TokenCodec::encode_debug(codec, &new_entry, verbose, Some(key), Some(caller))
}

#[cfg(test)]
#[path = "../../../tests/unit/feature_kv_entry_codec_test.rs"]
mod entry_codec_tests;
