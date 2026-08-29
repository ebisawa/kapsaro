// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! In-memory shape of a kv-enc document.
//! Holds the header, the wrapped keys, and one entry per stored key.

use crate::model::kv_enc::entry::KvEntryValue;
use crate::model::kv_enc::header::{KvHeader, KvWrap};
use crate::model::kv_enc::line::KvEncLine;
use crate::model::signature::ArtifactSignature;

pub type KvFileSignature = ArtifactSignature;

#[derive(Debug, Clone)]
pub struct KvEncEntry {
    key: String,
    token: String,
    value: KvEntryValue,
}

impl KvEncEntry {
    pub fn new(key: String, token: String, value: KvEntryValue) -> Self {
        Self { key, token, value }
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn value(&self) -> &KvEntryValue {
        &self.value
    }
}

#[derive(Debug, Clone)]
pub struct KvEncDocument {
    pub lines: Vec<KvEncLine>,
    pub head: KvHeader,
    pub wrap: KvWrap,
    pub wrap_token: String,
    pub entries: Vec<KvEncEntry>,
    pub signature_token: String,
    pub signature: KvFileSignature,
}

impl KvEncDocument {
    pub fn new(
        lines: Vec<KvEncLine>,
        head: KvHeader,
        wrap: KvWrap,
        wrap_token: String,
        entries: Vec<KvEncEntry>,
        signature_token: String,
        signature: KvFileSignature,
    ) -> Self {
        Self {
            lines,
            head,
            wrap,
            wrap_token,
            entries,
            signature_token,
            signature,
        }
    }

    /// Return the `:WRAP` token the document was parsed from.
    pub fn wrap_token(&self) -> &str {
        &self.wrap_token
    }

    pub fn lines(&self) -> &[KvEncLine] {
        &self.lines
    }

    pub fn head(&self) -> &KvHeader {
        &self.head
    }

    pub fn wrap(&self) -> &KvWrap {
        &self.wrap
    }

    pub fn entries(&self) -> &[KvEncEntry] {
        &self.entries
    }

    pub fn entry(&self, key: &str) -> Option<&KvEncEntry> {
        self.entries.iter().find(|entry| entry.key() == key)
    }

    pub fn signature_token(&self) -> &str {
        &self.signature_token
    }

    pub fn signature(&self) -> &KvFileSignature {
        &self.signature
    }
}
