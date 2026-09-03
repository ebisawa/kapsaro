// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key command output dispatchers.

pub(crate) mod view;

use crate::cli::common::output::json::key::{
    print_empty_key_list as print_empty_key_list_json, print_key_list as print_key_list_json,
};
use crate::cli::common::output::print_empty_or_json_or_text;
use crate::cli::common::output::text::key::{
    print_empty_key_list as print_empty_key_list_text, print_key_list as print_key_list_text,
};
use crate::cli::common::output::text::layout::{self, LineTarget};
use kapsaro_core::api::key::types::KeyListResult;
use kapsaro_core::Result;

/// Named on stderr beside an empty listing, so the listing stays machine
/// readable while the operator is still told what creates a key.
///
/// A keystore holding no key is an answer, not a fault, so this goes out as an
/// ordinary message rather than as a warning.
const EMPTY_KEY_LIST_HINT: &str = "No keys found. Run 'kapsaro key new' to generate a key.";

pub(crate) fn print_key_list(
    json_output: bool,
    result: &KeyListResult,
    verbose: bool,
) -> Result<()> {
    let view = view::build_key_list_view(result);
    let is_empty = view.entries.is_empty();
    print_empty_or_json_or_text(
        json_output,
        is_empty,
        print_empty_key_list_json,
        print_empty_key_list_text,
        || print_key_list_json(&view),
        || print_key_list_text(&view, verbose),
    )?;
    if is_empty {
        layout::print_lines(
            layout::format_value_lines("", EMPTY_KEY_LIST_HINT),
            LineTarget::Stderr,
        );
    }
    Ok(())
}
