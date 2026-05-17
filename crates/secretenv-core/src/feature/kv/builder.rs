// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV document builder for assembling unsigned kv-enc documents.

use crate::format::schema::document::{parse_kv_entry_token, parse_kv_wrap_token};
use crate::format::token::TokenCodec;
use crate::model::kv_enc::document::KvEncDocument;
use crate::model::kv_enc::header::{KvHeader, KvWrap};
use crate::model::kv_enc::line::KvEncLine;
use crate::{Error, Result};

use super::document::{KvDocumentDraft, KvDocumentEntry, WrapSource};
use super::types::KvEncodedEntry;

/// Builder for assembling a KV-enc document prior to signing.
pub struct KvDocumentBuilder {
    head: KvHeader,
    wrap: WrapSource,
    entries: Vec<KvDocumentEntry>,
    token_codec: TokenCodec,
    debug: bool,
}

impl KvDocumentBuilder {
    /// Create a new builder with decoded wrap data.
    pub fn new(head: KvHeader, wrap: KvWrap, token_codec: TokenCodec, debug: bool) -> Self {
        Self {
            head,
            wrap: WrapSource::Decoded(wrap),
            entries: Vec::new(),
            token_codec,
            debug,
        }
    }

    /// Build from a validated KV-enc document.
    pub fn from_document(
        head: KvHeader,
        wrap: Option<KvWrap>,
        doc: &KvEncDocument,
        token_codec: TokenCodec,
        debug: bool,
    ) -> Result<Self> {
        let wrap_source = Self::wrap_source_from_lines(wrap.as_ref(), doc.lines())?;
        let entries = doc
            .entries()
            .iter()
            .map(|entry| KvDocumentEntry::Preserved {
                key: entry.key().to_string(),
                token: entry.token().to_string(),
                value: entry.value().clone(),
            })
            .collect();

        Ok(Self {
            head,
            wrap: wrap_source,
            entries,
            token_codec,
            debug,
        })
    }

    /// Build from parsed KV-enc lines.
    ///
    /// * `wrap` — if `Some`, the WRAP line is stored as `Decoded`; if `None`,
    ///   the WRAP token is decoded from the raw line and stored as `Raw`.
    pub fn from_lines(
        head: KvHeader,
        wrap: Option<KvWrap>,
        lines: &[KvEncLine],
        token_codec: TokenCodec,
        debug: bool,
    ) -> Result<Self> {
        let mut entries = Vec::new();

        for line in lines {
            if let KvEncLine::KV { key, token } = line {
                entries.push(KvDocumentEntry::Preserved {
                    key: key.clone(),
                    token: token.clone(),
                    value: parse_kv_entry_token(token)?,
                });
            }
        }

        let wrap = Self::wrap_source_from_lines(wrap.as_ref(), lines)?;

        Ok(Self {
            head,
            wrap,
            entries,
            token_codec,
            debug,
        })
    }

    fn wrap_source_from_lines(wrap: Option<&KvWrap>, lines: &[KvEncLine]) -> Result<WrapSource> {
        lines
            .iter()
            .find_map(|line| match line {
                KvEncLine::Wrap { token } => Some(Self::resolve_wrap_source(wrap, token)),
                _ => None,
            })
            .ok_or_else(|| {
                Error::build_parse_error("WRAP line not found in document".to_string())
            })?
    }

    fn resolve_wrap_source(wrap: Option<&KvWrap>, token: &str) -> Result<WrapSource> {
        match wrap {
            Some(wrap) => Ok(WrapSource::Decoded(wrap.clone())),
            None => {
                let data = parse_kv_wrap_token(token)?;
                Ok(WrapSource::Raw {
                    data,
                    token: token.to_string(),
                })
            }
        }
    }

    /// Append entries as Encoded.
    pub fn with_entries<I, E>(mut self, entries: I) -> Self
    where
        I: IntoIterator<Item = E>,
        E: Into<KvEncodedEntry>,
    {
        for entry in entries {
            let KvEncodedEntry { key, token } = entry.into();
            self.entries.push(KvDocumentEntry::Encoded { key, token });
        }
        self
    }

    /// Consume the builder and produce an unsigned document.
    pub fn build(self) -> KvDocumentDraft {
        KvDocumentDraft {
            head: self.head,
            wrap: self.wrap,
            entries: self.entries,
            token_codec: self.token_codec,
            debug: self.debug,
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_kv_builder_test.rs"]
mod tests;
