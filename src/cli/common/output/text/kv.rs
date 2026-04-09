// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderers for KV commands.

use crate::cli::common::output::kv::view::{KvEntryView, KvKeyView};
use crate::cli::common::output::text::print_optional_status;

pub(crate) fn print_kv_key_list(keys: &[KvKeyView<'_>]) {
    for key in keys {
        if key.disclosed {
            println!("{} [DISCLOSED]", key.key);
        } else {
            println!("{}", key.key);
        }
    }
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
