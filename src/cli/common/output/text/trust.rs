// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderers for trust commands.

use crate::cli::common::output::text::layout;
use crate::cli::common::output::trust::view::{RecipientSetListItemView, TrustListItemView};
use kapsaro_core::cli_api::presentation::kid::format_kid_display_lossy;

pub(crate) fn print_known_key_list(items: &[TrustListItemView<'_>]) {
    print_lines(format_known_key_list_lines(items));
}

fn format_known_key_list_lines(items: &[TrustListItemView<'_>]) -> Vec<String> {
    let mut lines = Vec::new();
    for item in items {
        let value = format!(
            "{} {} (approved: {}, via: {})",
            item.member_handle,
            format_kid_display_lossy(item.kid),
            item.approved_at,
            item.approved_via
        );
        lines.extend(layout::format_value_lines("  ", &value));
    }
    lines.push(String::new());
    lines.push(format!("{} known key(s)", items.len()));
    lines
}

pub(crate) fn print_empty_known_key_list() {
    eprintln!("No known keys in trust store");
}

pub(crate) fn print_recipient_set_list(items: &[RecipientSetListItemView<'_>]) {
    print_lines(format_recipient_set_list_lines(items));
}

fn format_recipient_set_list_lines(items: &[RecipientSetListItemView<'_>]) -> Vec<String> {
    let mut lines = Vec::new();
    for item in items {
        lines.extend(layout::format_value_lines(
            "  ",
            &format!(
                "{} (approved: {}, via: {})",
                item.sid, item.approved_at, item.approved_via
            ),
        ));
        lines.extend(layout::format_value_lines(
            "    hash: ",
            item.recipient_set_hash,
        ));
        lines.push("    recipient kids:".to_string());
        for kid in item.recipient_kids {
            lines.extend(layout::format_value_lines(
                "      - ",
                &format_kid_display_lossy(kid),
            ));
        }
    }
    lines.push(String::new());
    lines.push(format!("{} recipient set(s)", items.len()));
    lines
}

pub(crate) fn print_empty_recipient_set_list() {
    eprintln!("No recipient sets in trust store");
}

pub(crate) fn print_trust_remove_summary(kid: &str, member_handle: &str) {
    let kid_display = format_kid_display_lossy(kid);
    let value = format!("Removed kid '{kid_display}' (member: {member_handle}) from trust store");
    print_lines(layout::format_value_lines("", &value));
}

pub(crate) fn print_recipient_set_remove_summary(sid: &str) {
    let value = format!("Removed recipient set '{sid}' from trust store");
    print_lines(layout::format_value_lines("", &value));
}

pub(crate) fn print_no_entries_to_purge() {
    eprintln!("No entries to purge");
}

pub(crate) fn print_trust_purge_candidates(items: &[TrustListItemView<'_>]) {
    print_lines(format_trust_purge_candidate_lines(items));
}

fn format_trust_purge_candidate_lines(items: &[TrustListItemView<'_>]) -> Vec<String> {
    let mut lines = vec!["Entries to purge:".to_string()];
    for item in items {
        let value = format!(
            "{} {} (approved: {})",
            item.member_handle,
            format_kid_display_lossy(item.kid),
            item.approved_at
        );
        lines.extend(layout::format_value_lines("  ", &value));
    }
    lines.push(String::new());
    lines.push(format!("{} entry(ies) will be removed", items.len()));
    lines
}

pub(crate) fn print_recipient_set_purge_candidates(items: &[RecipientSetListItemView<'_>]) {
    print_lines(format_recipient_set_purge_candidate_lines(items));
}

fn format_recipient_set_purge_candidate_lines(
    items: &[RecipientSetListItemView<'_>],
) -> Vec<String> {
    let mut lines = vec!["Recipient sets to purge:".to_string()];
    for item in items {
        lines.extend(layout::format_value_lines(
            "  ",
            &format!("{} (approved: {})", item.sid, item.approved_at),
        ));
    }
    lines.push(String::new());
    lines.push(format!("{} recipient set(s) will be removed", items.len()));
    lines
}

pub(crate) fn print_purge_cancelled() {
    eprintln!("Purge cancelled");
}

pub(crate) fn print_trust_purge_summary(count: usize) {
    eprintln!("Purged {} entry(ies)", count);
}

pub(crate) fn print_recipient_set_purge_summary(count: usize) {
    eprintln!("Purged {} recipient set(s)", count);
}

fn print_lines(lines: Vec<String>) {
    for line in lines {
        eprintln!("{line}");
    }
}

#[cfg(test)]
#[path = "../../../../../tests/unit/internal/cli_common_output_text_trust_test.rs"]
mod tests;
