// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderers for KV commands.

use crate::cli::common::output::kv::view::{KvEntryView, KvKeyView};
use crate::cli::common::output::text::layout::LineTarget;
use crate::cli::common::output::text::{layout, print_optional_status};

pub(crate) fn print_kv_key_list(keys: &[KvKeyView<'_>]) {
    layout::print_lines(format_kv_key_list_lines(keys), LineTarget::Stdout);
}

pub(crate) fn print_all_kv_values(entries: &[KvEntryView<'_>], with_key: bool) {
    for entry in entries {
        print_value(entry.key, entry.value, with_key);
    }
}

pub(crate) fn print_single_kv_value(key: &str, value: &str, with_key: bool) {
    print_value(key, value, with_key);
}

pub(crate) fn print_import_summary(message: Option<&str>, entry_count: usize, quiet: bool) {
    if let Some(message) = message {
        print_optional_status(Some(message), quiet);
    } else if !quiet {
        eprintln!("Imported {} entries", entry_count);
    }
}

fn print_value(key: &str, value: &str, with_key: bool) {
    if !with_key {
        println!("{value}");
        return;
    }

    print!("{key}=\"");
    print_escaped_value(value);
    println!("\"");
}

fn print_escaped_value(value: &str) {
    for ch in value.chars() {
        match ch {
            '\\' => print!("\\\\"),
            '"' => print!("\\\""),
            _ => print!("{ch}"),
        }
    }
}

fn format_kv_key_list_lines(keys: &[KvKeyView<'_>]) -> Vec<String> {
    keys.iter()
        .flat_map(|key| {
            if key.disclosed {
                layout::format_value_lines("", &format!("{} [DISCLOSED]", key.key))
            } else {
                layout::format_value_lines("", key.key)
            }
        })
        .collect()
}

#[cfg(test)]
#[path = "../../../../../tests/unit/internal/cli_common_output_text_kv_test.rs"]
mod tests;
