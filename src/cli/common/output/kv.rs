// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV command output helpers.

pub(crate) mod view;

use crate::cli::common::output::json::kv::{
    print_all_kv_values as print_all_kv_values_json,
    print_kv_import_result as print_kv_import_result_json,
    print_kv_key_list as print_kv_key_list_json,
    print_single_kv_value as print_single_kv_value_json,
};
use crate::cli::common::output::print_json_or_text;
use crate::cli::common::output::text::kv::{
    print_all_kv_values as print_all_kv_values_text, print_import_summary,
    print_kv_key_list as print_kv_key_list_text,
    print_single_kv_value as print_single_kv_value_text,
};
use crate::cli::common::output::text::print_warning_line;
use secretenv_core::cli_api::app::kv::types::{KvDisclosedEntry, KvReadResult};
use secretenv_core::Result;

pub(crate) fn print_kv_key_list(keys: &[KvDisclosedEntry], json_output: bool) -> Result<()> {
    let key_views = view::build_kv_key_views(keys);
    print_json_or_text(
        json_output,
        || print_kv_key_list_json(&key_views),
        || print_kv_key_list_text(&key_views),
    )
}

pub(crate) fn print_kv_read_result(
    result: &KvReadResult,
    key: Option<&str>,
    json_output: bool,
    with_key: bool,
) -> Result<()> {
    match key {
        Some(key) => print_single_kv_value(result, key, json_output, with_key),
        None => print_all_kv_values(result, json_output, with_key),
    }
}

pub(crate) fn print_kv_import_result(
    message: Option<&str>,
    entry_count: usize,
    store_name: &str,
    json_output: bool,
    quiet: bool,
) -> Result<()> {
    print_json_or_text(
        json_output,
        || print_kv_import_result_json(entry_count, store_name),
        || {
            print_import_summary(message, entry_count, quiet);
        },
    )
}

fn print_all_kv_values(result: &KvReadResult, json_output: bool, with_key: bool) -> Result<()> {
    let entries = view::build_kv_entries(result);
    print_disclosed_key_warnings(&entries);
    print_json_or_text(
        json_output,
        || print_all_kv_values_json(&entries),
        || print_all_kv_values_text(&entries, with_key),
    )
}

fn print_single_kv_value(
    result: &KvReadResult,
    key: &str,
    json_output: bool,
    with_key: bool,
) -> Result<()> {
    let entry = view::build_single_kv_entry(result, key);
    print_disclosed_key_warning(entry.key, entry.disclosed);
    print_json_or_text(
        json_output,
        || print_single_kv_value_json(entry.key, entry.value),
        || print_single_kv_value_text(entry.key, entry.value, with_key),
    )
}

fn print_disclosed_key_warnings(entries: &[view::KvEntryView<'_>]) {
    for entry in entries {
        print_disclosed_key_warning(entry.key, entry.disclosed);
    }
}

fn print_disclosed_key_warning(key: &str, disclosed: bool) {
    if disclosed {
        print_warning_line(&format!(
            "Warning: Entry '{}' may have been disclosed to a removed recipient. \
             Consider rotating the secret value.",
            key
        ));
    }
}
