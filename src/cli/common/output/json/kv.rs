// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! JSON renderers for KV commands.

use crate::cli::common::output::json::print_json_output;
use crate::cli::common::output::kv::view::{KvEntryView, KvKeyView};
use crate::Result;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
struct KvKeyListOutput<'a> {
    keys: Vec<&'a str>,
}

#[derive(Serialize)]
struct ImportOutput<'a> {
    imported: usize,
    file: &'a str,
}

pub(crate) fn print_kv_key_list(keys: &[KvKeyView<'_>]) -> Result<()> {
    print_json_output(&KvKeyListOutput {
        keys: keys.iter().map(|item| item.key).collect(),
    })
}

pub(crate) fn print_kv_import_result(entry_count: usize, store_name: &str) -> Result<()> {
    print_json_output(&ImportOutput {
        imported: entry_count,
        file: store_name,
    })
}

pub(crate) fn print_all_kv_values(entries: &[KvEntryView<'_>]) -> Result<()> {
    let map: BTreeMap<&str, &str> = entries
        .iter()
        .map(|entry| (entry.key, entry.value))
        .collect();
    print_json_output(&map)
}

pub(crate) fn print_single_kv_value(key: &str, value: &str) -> Result<()> {
    let mut map = BTreeMap::new();
    map.insert(key, value);
    print_json_output(&map)
}
