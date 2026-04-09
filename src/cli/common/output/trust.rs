// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust command output dispatchers.

pub(crate) mod review;
pub(crate) mod view;

use std::collections::BTreeSet;

use crate::app::trust::list::TrustListResult;
use crate::app::trust::management::PurgeKnownKeysResult;
use crate::cli::common::output::json::trust::print_known_key_list as print_known_key_list_json;
use crate::cli::common::output::print_empty_or_json_or_text_with_warnings;
use crate::cli::common::output::text::trust::{
    print_empty_known_key_list, print_known_key_list as print_known_key_list_text,
    print_no_entries_to_purge, print_trust_purge_candidates, print_trust_purge_summary,
};
use crate::Result;
pub(crate) use view::TrustListItemView;

pub(crate) fn print_trust_list(json_output: bool, result: &TrustListResult) -> Result<()> {
    let items = view::build_trust_list_views(&result.items);
    print_empty_or_json_or_text_with_warnings(
        json_output,
        items.is_empty(),
        &result.warnings,
        || print_known_key_list_json(&[]),
        print_empty_known_key_list,
        || print_known_key_list_json(&items),
        || print_known_key_list_text(&items),
    )
}

pub(crate) fn print_trust_purge_preview(
    result: &TrustListResult,
    shown_warnings: &mut BTreeSet<String>,
) -> bool {
    print_unique_warnings(&result.warnings, shown_warnings);
    if result.items.is_empty() {
        print_no_entries_to_purge();
        return false;
    }

    print_trust_purge_candidates(&view::build_trust_list_views(&result.items));
    true
}

pub(crate) fn print_trust_purge_outcome(
    result: &PurgeKnownKeysResult,
    shown_warnings: &mut BTreeSet<String>,
) {
    print_unique_warnings(&result.warnings, shown_warnings);
    print_trust_purge_summary(result.value);
}

fn print_unique_warnings(warnings: &[String], shown: &mut BTreeSet<String>) {
    for warning in warnings {
        if shown.insert(warning.clone()) {
            eprintln!("Warning: {}", warning);
        }
    }
}
