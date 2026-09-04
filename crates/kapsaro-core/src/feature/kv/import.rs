// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Turns dotenv text into the KV entries a write takes.
//! Rejects the whole document when any line is malformed, rather than skipping it.

use std::collections::BTreeMap;

use crate::feature::kv::types::KvInputEntry;
use crate::format::kv::dotenv::{parse_dotenv, validate_dotenv_strict};
use crate::Result;

/// Parse a dotenv document into the entries a KV write takes.
///
/// Strict validation runs first, so a line the lenient parser would drop is
/// reported instead of leaving the caller with fewer entries than it wrote. The
/// entries are collected through an ordered map, so the same document always
/// produces the same sequence of writes.
pub fn parse_dotenv_entries(content: &str) -> Result<Vec<KvInputEntry>> {
    validate_dotenv_strict(content)?;
    let ordered: BTreeMap<_, _> = parse_dotenv(content)?.into_iter().collect();
    Ok(ordered
        .into_iter()
        .map(|(key, value)| KvInputEntry::new_secret(key, value))
        .collect())
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_kv_import_test.rs"]
mod feature_kv_import_test;
