// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::feature::kv::query::KvDisclosedEntry;
use crate::support::secret::SecretString;

#[derive(Debug)]
pub struct KvWriteOutcome {
    pub message: Option<String>,
}

pub(crate) struct KvReadResult {
    pub values: BTreeMap<String, SecretString>,
    pub disclosed: Vec<KvDisclosedEntry>,
}

#[derive(Debug)]
pub struct KvImportResult {
    pub write_outcome: KvWriteOutcome,
    pub entry_count: usize,
}

#[derive(Clone, Copy)]
pub(crate) enum KvReadMode<'a> {
    All,
    Single(&'a str),
}
