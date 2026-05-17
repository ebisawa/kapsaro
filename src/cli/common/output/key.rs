// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key command output dispatchers.

pub(crate) mod view;

pub(crate) use view::{KeyInfoView, KeyListView};

use crate::cli::common::output::json::key::{
    print_empty_key_list as print_empty_key_list_json, print_key_list as print_key_list_json,
};
use crate::cli::common::output::print_empty_or_json_or_text;
use crate::cli::common::output::text::key::{
    print_empty_key_list as print_empty_key_list_text, print_key_list as print_key_list_text,
};
use secretenv_core::cli_api::app::key::types::KeyListResult;
use secretenv_core::Result;

pub(crate) fn print_key_list(
    json_output: bool,
    result: &KeyListResult,
    verbose: bool,
) -> Result<()> {
    let view = view::build_key_list_view(result);
    print_empty_or_json_or_text(
        json_output,
        view.entries.is_empty(),
        print_empty_key_list_json,
        print_empty_key_list_text,
        || print_key_list_json(&view),
        || print_key_list_text(&view, verbose),
    )
}
