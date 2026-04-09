// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! View builders for KV command output.

use crate::app::kv::types::KvReadResult;
use crate::feature::kv::query::KvDisclosedEntry;
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

pub(crate) struct KvValueView<'a> {
    pub(crate) key: &'a str,
    pub(crate) value: &'a str,
    pub(crate) disclosed: bool,
}

pub(crate) fn build_kv_key_views(keys: &[KvDisclosedEntry]) -> Vec<KvKeyView<'_>> {
    keys.iter()
        .map(|entry| KvKeyView {
            key: entry.key.as_str(),
            disclosed: entry.disclosed,
        })
        .collect()
}

pub(crate) fn build_kv_entries(result: &KvReadResult) -> Vec<KvEntryView<'_>> {
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

pub(crate) fn build_single_kv_value<'a>(result: &'a KvReadResult, key: &'a str) -> KvValueView<'a> {
    KvValueView {
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

pub(crate) fn print_disclosed_key_warnings(entries: &[KvEntryView<'_>]) {
    for entry in entries {
        print_disclosed_key_warning(entry);
    }
}

pub(crate) fn print_disclosed_key_warning(entry: &impl KvDisclosureWarning) {
    if entry.disclosed() {
        eprintln!(
            "Warning: Entry '{}' may have been disclosed to a removed recipient. \
             Consider rotating the secret value.",
            entry.key()
        );
    }
}

pub(crate) trait KvDisclosureWarning {
    fn key(&self) -> &str;
    fn disclosed(&self) -> bool;
}

impl KvDisclosureWarning for KvEntryView<'_> {
    fn key(&self) -> &str {
        self.key
    }

    fn disclosed(&self) -> bool {
        self.disclosed
    }
}

impl KvDisclosureWarning for KvValueView<'_> {
    fn key(&self) -> &str {
        self.key
    }

    fn disclosed(&self) -> bool {
        self.disclosed
    }
}

fn disclosed_lookup(disclosed: &[KvDisclosedEntry]) -> BTreeMap<&str, bool> {
    disclosed
        .iter()
        .map(|entry| (entry.key.as_str(), entry.disclosed))
        .collect()
}
