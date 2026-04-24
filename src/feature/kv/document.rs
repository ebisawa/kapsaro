// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unsigned KV document state and serialization helpers.

use crate::format::kv::enc::writer::build_unsigned_kv_document;
use crate::format::schema::document::parse_kv_entry_token;
use crate::format::token::TokenCodec;
use crate::model::kv_enc::header::{KvHeader, KvWrap};
use crate::Result;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub(crate) enum KvDocumentEntry {
    Preserved { key: String, token: String },
    Encoded { key: String, token: String },
}

impl KvDocumentEntry {
    pub fn key(&self) -> &str {
        match self {
            Self::Preserved { key, .. } | Self::Encoded { key, .. } => key,
        }
    }

    pub fn token(&self) -> &str {
        match self {
            Self::Preserved { token, .. } | Self::Encoded { token, .. } => token,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum WrapSource {
    Decoded(KvWrap),
    Raw { data: KvWrap, token: String },
}

impl WrapSource {
    pub fn data(&self) -> &KvWrap {
        match self {
            Self::Decoded(data) => data,
            Self::Raw { data, .. } => data,
        }
    }

    pub fn data_mut(&mut self) -> &mut KvWrap {
        if let Self::Raw { data, .. } = self {
            let owned = data.clone();
            *self = Self::Decoded(owned);
        }
        match self {
            Self::Decoded(data) => data,
            Self::Raw { .. } => unreachable!(),
        }
    }
}

pub struct KvDocumentDraft {
    pub(crate) head: KvHeader,
    pub(crate) wrap: WrapSource,
    pub(crate) entries: Vec<KvDocumentEntry>,
    pub(crate) token_codec: TokenCodec,
    pub(crate) debug: bool,
}

impl KvDocumentDraft {
    pub fn head(&self) -> &KvHeader {
        &self.head
    }

    pub fn wrap(&self) -> &KvWrap {
        self.wrap.data()
    }

    pub fn wrap_mut(&mut self) -> &mut KvWrap {
        self.wrap.data_mut()
    }

    pub fn entry_keys(&self) -> Vec<&str> {
        self.entries.iter().map(|entry| entry.key()).collect()
    }

    pub fn has_entry(&self, key: &str) -> bool {
        self.entries.iter().any(|entry| entry.key() == key)
    }

    pub fn set_entries(&mut self, entries: &HashMap<&str, &str>) {
        let mut found: HashSet<&str> = HashSet::new();

        for entry in &mut self.entries {
            if let Some((&matched_key, &new_token)) = entries.get_key_value(entry.key()) {
                found.insert(matched_key);
                *entry = KvDocumentEntry::Encoded {
                    key: entry.key().to_string(),
                    token: new_token.to_string(),
                };
            }
        }

        let mut new_keys: Vec<_> = entries
            .iter()
            .filter(|(key, _)| !found.contains(**key))
            .collect();
        new_keys.sort_by_key(|(key, _)| **key);

        for (key, token) in new_keys {
            self.entries.push(KvDocumentEntry::Encoded {
                key: key.to_string(),
                token: token.to_string(),
            });
        }
    }

    pub fn unset_entry(&mut self, key: &str) {
        self.entries.retain(|entry| entry.key() != key);
    }

    pub fn update_timestamp(&mut self) -> Result<()> {
        self.head.updated_at = crate::support::time::generate_current_timestamp()?;
        Ok(())
    }

    pub fn set_wrap(&mut self, wrap: KvWrap) {
        self.wrap = WrapSource::Decoded(wrap);
    }

    pub(crate) fn token_codec(&self) -> TokenCodec {
        self.token_codec
    }

    pub fn clear_disclosed_flags(&mut self) -> Result<()> {
        for entry in &mut self.entries {
            if let KvDocumentEntry::Preserved { key, token } = entry {
                let mut value = parse_kv_entry_token(token)?;
                if value.disclosed {
                    value.disclosed = false;
                    let new_token = TokenCodec::encode(self.token_codec, &value)?;
                    *entry = KvDocumentEntry::Encoded {
                        key: key.clone(),
                        token: new_token,
                    };
                }
            }
        }
        Ok(())
    }

    pub fn serialize_unsigned(&self) -> Result<String> {
        let head_token = self.encode_head()?;
        let wrap_token = self.resolve_wrap_token()?;
        let entries: Vec<(&str, &str)> = self
            .entries
            .iter()
            .map(|entry| (entry.key(), entry.token()))
            .collect();

        Ok(build_unsigned_kv_document(
            &head_token,
            &wrap_token,
            &entries,
        ))
    }

    fn encode_head(&self) -> Result<String> {
        TokenCodec::encode_debug(
            self.token_codec,
            &self.head,
            self.debug,
            Some("HEAD"),
            Some("serialize_unsigned"),
        )
    }

    fn resolve_wrap_token(&self) -> Result<String> {
        match &self.wrap {
            WrapSource::Decoded(data) => TokenCodec::encode_debug(
                self.token_codec,
                data,
                self.debug,
                Some("WRAP"),
                Some("serialize_unsigned"),
            ),
            WrapSource::Raw { token, .. } => Ok(token.clone()),
        }
    }
}
