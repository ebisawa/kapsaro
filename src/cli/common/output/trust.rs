// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust command output dispatchers.

pub(crate) mod review;
pub(crate) mod view;

use std::collections::BTreeSet;

use crate::cli::common::output::json::trust::print_known_key_list as print_known_key_list_json;
use crate::cli::common::output::json::trust::print_recipient_set_list as print_recipient_set_list_json;
use crate::cli::common::output::print_empty_or_json_or_text_with_warnings;
use crate::cli::common::output::text::print_warning;
use crate::cli::common::output::text::trust::{
    print_empty_known_key_list, print_empty_recipient_set_list,
    print_known_key_list as print_known_key_list_text, print_no_entries_to_purge,
    print_recipient_set_list as print_recipient_set_list_text,
    print_recipient_set_purge_candidates, print_recipient_set_purge_summary,
    print_trust_purge_candidates, print_trust_purge_summary,
};
use secretenv_core::cli_api::app::trust::list::{RecipientSetListResult, TrustListResult};
use secretenv_core::cli_api::app::trust::management::{
    PurgeKnownKeysResult, PurgeRecipientSetsResult,
};
use secretenv_core::Result;
pub(crate) use view::{RecipientSetListItemView, TrustListItemView};

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

pub(crate) fn print_recipient_set_list(
    json_output: bool,
    result: &RecipientSetListResult,
) -> Result<()> {
    let items = view::build_recipient_set_list_views(&result.items);
    print_empty_or_json_or_text_with_warnings(
        json_output,
        items.is_empty(),
        &result.warnings,
        || print_recipient_set_list_json(&[]),
        print_empty_recipient_set_list,
        || print_recipient_set_list_json(&items),
        || print_recipient_set_list_text(&items),
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

pub(crate) fn print_recipient_set_purge_preview(
    result: &RecipientSetListResult,
    shown_warnings: &mut BTreeSet<String>,
) -> bool {
    print_unique_warnings(&result.warnings, shown_warnings);
    if result.items.is_empty() {
        print_no_entries_to_purge();
        return false;
    }

    print_recipient_set_purge_candidates(&view::build_recipient_set_list_views(&result.items));
    true
}

pub(crate) fn print_trust_purge_outcome(
    result: &PurgeKnownKeysResult,
    shown_warnings: &mut BTreeSet<String>,
) {
    print_unique_warnings(&result.warnings, shown_warnings);
    print_trust_purge_summary(result.value);
}

pub(crate) fn print_recipient_set_purge_outcome(
    result: &PurgeRecipientSetsResult,
    shown_warnings: &mut BTreeSet<String>,
) {
    print_unique_warnings(&result.warnings, shown_warnings);
    print_recipient_set_purge_summary(result.value);
}

fn print_unique_warnings(warnings: &[String], shown: &mut BTreeSet<String>) {
    for warning in warnings {
        if shown.insert(warning.clone()) {
            print_warning(warning);
        }
    }
}
