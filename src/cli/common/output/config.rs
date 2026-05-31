// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Config command output helpers.

use kapsaro_core::cli_api::app::config::{ConfigScope, ConfigSetResult, ConfigUnsetResult};
use std::collections::BTreeMap;

pub(crate) fn print_config_value(value: &str) {
    println!("{}", value);
}

pub(crate) fn print_config_list(values: &BTreeMap<String, String>) {
    for (key, value) in values {
        println!("{} = {}", key, value);
    }
}

pub(crate) fn print_config_set_result(result: &ConfigSetResult) {
    eprintln!(
        "Set '{}' = '{}' in {} config",
        result.key,
        result.value,
        scope_label(result.scope)
    );
}

pub(crate) fn print_config_unset_result(result: &ConfigUnsetResult) {
    eprintln!(
        "Unset '{}' from {} config",
        result.key,
        scope_label(result.scope)
    );
}

fn scope_label(scope: ConfigScope) -> &'static str {
    match scope {
        ConfigScope::Global => "global",
    }
}
