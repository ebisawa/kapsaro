// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared KV feature DTOs.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvInputEntry {
    pub key: String,
    pub value: String,
}

impl KvInputEntry {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvEncodedEntry {
    pub key: String,
    pub token: String,
}

impl From<(String, String)> for KvEncodedEntry {
    fn from((key, token): (String, String)) -> Self {
        Self { key, token }
    }
}
