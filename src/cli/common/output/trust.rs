// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust command output dispatchers.

pub(crate) mod review;
pub(crate) mod view;

use crate::cli::common::output::json::trust::print_known_key_list as print_known_key_list_json;
use crate::cli::common::output::json::trust::print_recipient_set_list as print_recipient_set_list_json;
use crate::cli::common::output::print_empty_or_json_or_text;
use crate::cli::common::output::text::trust::{
    print_empty_known_key_list, print_empty_recipient_set_list,
    print_known_key_list as print_known_key_list_text, print_no_entries_to_purge,
    print_recipient_set_list as print_recipient_set_list_text,
    print_recipient_set_purge_candidates, print_recipient_set_purge_summary,
    print_trust_purge_candidates, print_trust_purge_resigned, print_trust_purge_summary,
};
use kapsaro_core::api::trust::list::{
    RecipientSetListItem, RecipientSetListResult, TrustListItem, TrustListResult,
};
use kapsaro_core::api::trust::management::{PurgeOutcome, ReviewedPurgeCandidates};
use kapsaro_core::Result;

pub(crate) fn print_trust_list(json_output: bool, result: &TrustListResult) -> Result<()> {
    let items = view::build_trust_list_views(&result.items);
    print_empty_or_json_or_text(
        json_output,
        items.is_empty(),
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
    print_empty_or_json_or_text(
        json_output,
        items.is_empty(),
        || print_recipient_set_list_json(&[]),
        print_empty_recipient_set_list,
        || print_recipient_set_list_json(&items),
        || print_recipient_set_list_text(&items),
    )
}

pub(crate) fn print_trust_purge_preview(result: &ReviewedPurgeCandidates<TrustListItem>) -> bool {
    if result.items.is_empty() {
        print_no_entries_to_purge();
        return false;
    }

    print_trust_purge_candidates(&view::build_trust_list_views(&result.items));
    true
}

pub(crate) fn print_recipient_set_purge_preview(
    result: &ReviewedPurgeCandidates<RecipientSetListItem>,
) -> bool {
    if result.items.is_empty() {
        print_no_entries_to_purge();
        return false;
    }

    print_recipient_set_purge_candidates(&view::build_recipient_set_list_views(&result.items));
    true
}

pub(crate) fn print_trust_purge_outcome(outcome: &PurgeOutcome) {
    print_trust_purge_summary(outcome.removed);
    report_purge_resigned(outcome);
}

pub(crate) fn print_recipient_set_purge_outcome(outcome: &PurgeOutcome) {
    print_recipient_set_purge_summary(outcome.removed);
    report_purge_resigned(outcome);
}

/// Say that the purge moved the stored signature, which it does whenever the
/// signing key has changed since the store was last written.
///
/// The signature moves whether or not anything was removed, so a purge that
/// removed nothing still rewrites the file. Reporting only the count would let
/// that write pass unmentioned.
fn report_purge_resigned(outcome: &PurgeOutcome) {
    if !outcome.resigned {
        return;
    }
    print_trust_purge_resigned();
}
