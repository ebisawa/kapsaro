// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Result types the KV use cases hand back to the CLI.
//! Carries entries and outcomes in the shape the presentation layer renders.

use crate::feature::kv::types as feature_types;
use crate::support::secret::SecretString;

#[derive(Debug, PartialEq, Eq)]
pub struct KvInputEntry {
    pub key: String,
    pub value: SecretString,
}

impl KvInputEntry {
    /// Build an entry from a plain value.
    ///
    /// Production callers hold a `SecretString` already and use `new_secret`.
    /// This one exists so a test can spell an expected entry inline.
    #[cfg(test)]
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new_secret(key, SecretString::new(value.into()))
    }

    pub fn new_secret(key: impl Into<String>, value: SecretString) -> Self {
        Self {
            key: key.into(),
            value,
        }
    }

    pub(crate) fn into_feature(self) -> feature_types::KvInputEntry {
        feature_types::KvInputEntry {
            key: self.key,
            value: self.value,
        }
    }
}

#[derive(Debug)]
pub struct KvWriteOutcome {
    pub message: Option<String>,
}

#[derive(Debug)]
pub struct KvImportResult {
    pub write_outcome: KvWriteOutcome,
    pub entry_count: usize,
}
