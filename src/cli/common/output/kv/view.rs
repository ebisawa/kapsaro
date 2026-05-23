// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! View builders for KV command output.

use secretenv_core::cli_api::app::kv::types::{KvDisclosedEntry, KvReadResult};
use std::collections::BTreeMap;

pub(crate) struct KvKeyView<'a> {
    pub(crate) key: &'a str,
    pub(crate) disclosed: bool,
}

pub(crate) struct KvEntryView<'a> {
    pub(crate) key: &'a str,
    pub(crate) value: &'a str,
    pub(crate) disclosed: bool,
}

pub(super) fn build_kv_key_views(keys: &[KvDisclosedEntry]) -> Vec<KvKeyView<'_>> {
    keys.iter()
        .map(|entry| KvKeyView {
            key: entry.key.as_str(),
            disclosed: entry.disclosed,
        })
        .collect()
}

pub(super) fn build_kv_entries(result: &KvReadResult) -> Vec<KvEntryView<'_>> {
    let disclosed = disclosed_lookup(&result.disclosed);
    result
        .values
        .iter()
        .map(|(key, value)| KvEntryView {
            key: key.as_str(),
            value: value.as_str(),
            disclosed: disclosed.get(key.as_str()).copied().unwrap_or(false),
        })
        .collect()
}

pub(super) fn build_single_kv_entry<'a>(result: &'a KvReadResult, key: &'a str) -> KvEntryView<'a> {
    KvEntryView {
        key,
        value: result
            .values
            .get(key)
            .map(|value| value.as_str())
            .unwrap_or_default(),
        disclosed: result
            .disclosed
            .iter()
            .any(|entry| entry.key == key && entry.disclosed),
    }
}

fn disclosed_lookup(disclosed: &[KvDisclosedEntry]) -> BTreeMap<&str, bool> {
    disclosed
        .iter()
        .map(|entry| (entry.key.as_str(), entry.disclosed))
        .collect()
}
