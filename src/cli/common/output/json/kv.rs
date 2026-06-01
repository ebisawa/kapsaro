// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! JSON renderers for KV commands.

use crate::cli::common::output::json::print_json_output;
use crate::cli::common::output::kv::view::{KvEntryView, KvKeyView};
use kapsaro_core::Result;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
struct KvKeyListOutput<'a> {
    keys: Vec<&'a str>,
}

#[derive(Serialize)]
struct ImportOutput<'a> {
    success: bool,
    summary: ImportSummaryOutput<'a>,
}

#[derive(Serialize)]
struct ImportSummaryOutput<'a> {
    imported: usize,
    file: &'a str,
}

#[derive(Serialize)]
struct KvValuesOutput<'a> {
    values: BTreeMap<&'a str, &'a str>,
}

pub(crate) fn print_kv_key_list(keys: &[KvKeyView<'_>]) -> Result<()> {
    print_json_output(&KvKeyListOutput {
        keys: keys.iter().map(|item| item.key).collect(),
    })
}

pub(crate) fn print_kv_import_result(entry_count: usize, store_name: &str) -> Result<()> {
    print_json_output(&ImportOutput {
        success: true,
        summary: ImportSummaryOutput {
            imported: entry_count,
            file: store_name,
        },
    })
}

pub(crate) fn print_all_kv_values(entries: &[KvEntryView<'_>]) -> Result<()> {
    let values = entries
        .iter()
        .map(|entry| (entry.key, entry.value))
        .collect();
    print_json_output(&KvValuesOutput { values })
}

pub(crate) fn print_single_kv_value(key: &str, value: &str) -> Result<()> {
    let mut values = BTreeMap::new();
    values.insert(key, value);
    print_json_output(&KvValuesOutput { values })
}
