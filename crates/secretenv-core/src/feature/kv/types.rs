// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared KV feature DTOs.

use crate::support::secret::SecretString;

#[derive(Debug, PartialEq, Eq)]
pub struct KvInputEntry {
    pub key: String,
    pub value: SecretString,
}

impl KvInputEntry {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new_secret(key, SecretString::new(value.into()))
    }

    pub fn new_secret(key: impl Into<String>, value: SecretString) -> Self {
        Self {
            key: key.into(),
            value,
        }
    }
}
