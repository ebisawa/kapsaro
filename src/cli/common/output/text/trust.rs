// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderers for trust commands.

use crate::cli::common::output::text::layout;
use crate::cli::common::output::text::layout::{KidDisplayFallback, LineTarget};
use crate::cli::common::output::trust::view::{RecipientSetListItemView, TrustListItemView};

pub(crate) fn print_known_key_list(items: &[TrustListItemView<'_>]) {
    layout::print_lines(format_known_key_list_lines(items), LineTarget::Stderr);
}

fn format_known_key_list_lines(items: &[TrustListItemView<'_>]) -> Vec<String> {
    let mut lines = Vec::new();
    for item in items {
        let value = format!(
            "{} {} (approved: {}, via: {})",
            item.member_handle,
            layout::format_kid_display_text(item.kid, KidDisplayFallback::Sanitized),
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
    layout::print_lines(format_recipient_set_list_lines(items), LineTarget::Stderr);
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
                &layout::format_kid_display_text(kid, KidDisplayFallback::Sanitized),
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
    let kid_display = layout::format_kid_display_text(kid, KidDisplayFallback::Sanitized);
    let value = format!("Removed kid '{kid_display}' (member: {member_handle}) from trust store");
    layout::print_lines(layout::format_value_lines("", &value), LineTarget::Stderr);
}

/// Report that the local trust store signature moved to another key.
pub(crate) fn print_trust_store_resigned(signer_kid: &str) {
    let kid_display = layout::format_kid_display_text(signer_kid, KidDisplayFallback::Sanitized);
    let value = format!("Re-signed local trust store with kid '{kid_display}'");
    layout::print_lines(layout::format_value_lines("", &value), LineTarget::Stderr);
}

/// Report that the local trust store is still signed by a key other than the
/// one just activated, so that key has to stay in the keystore until it is
/// re-signed.
pub(crate) fn print_trust_store_signer_notice(signer_kid: &str, member_handle: &str) {
    let kid_display = layout::format_kid_display_text(signer_kid, KidDisplayFallback::Sanitized);
    let value = format!(
        "Local trust store is still signed by kid '{kid_display}'. \
         Run 'kapsaro trust resign --member-handle {member_handle}' to move the signature to the \
         active key."
    );
    layout::print_lines(layout::format_value_lines("", &value), LineTarget::Stderr);
}

/// Report the outcome of an explicit `trust resign` run.
pub(crate) fn print_trust_resign_summary(
    owner_handle: &str,
    previous_signer_kid: &str,
    signer_kid: &str,
    resigned: bool,
) {
    let value = if resigned {
        format!(
            "Re-signed local trust store for '{}': {} -> {}",
            owner_handle,
            layout::format_kid_display_text(previous_signer_kid, KidDisplayFallback::Sanitized),
            layout::format_kid_display_text(signer_kid, KidDisplayFallback::Sanitized)
        )
    } else {
        format!(
            "Local trust store for '{}' is already signed by kid '{}'",
            owner_handle,
            layout::format_kid_display_text(signer_kid, KidDisplayFallback::Sanitized)
        )
    };
    layout::print_lines(layout::format_value_lines("", &value), LineTarget::Stderr);
}

pub(crate) fn print_recipient_set_remove_summary(sid: &str) {
    let value = format!("Removed recipient set '{sid}' from trust store");
    layout::print_lines(layout::format_value_lines("", &value), LineTarget::Stderr);
}

/// Report that the reset already took the entry the operator asked to remove.
///
/// Running the removal again against the empty store the reset left behind
/// would report the entry as missing, which reads as a failed command when what
/// the operator asked for has in fact happened.
pub(crate) fn print_key_removed_by_reset() {
    let value = "Trust store was reset, so there was no approved key left to remove";
    layout::print_lines(layout::format_value_lines("", value), LineTarget::Stderr);
}

pub(crate) fn print_recipient_set_removed_by_reset() {
    let value = "Trust store was reset, so there was no recipient set left to remove";
    layout::print_lines(layout::format_value_lines("", value), LineTarget::Stderr);
}

pub(crate) fn print_no_entries_to_purge() {
    eprintln!("No entries to purge");
}

pub(crate) fn print_trust_purge_candidates(items: &[TrustListItemView<'_>]) {
    layout::print_lines(
        format_trust_purge_candidate_lines(items),
        LineTarget::Stderr,
    );
}

fn format_trust_purge_candidate_lines(items: &[TrustListItemView<'_>]) -> Vec<String> {
    let mut lines = vec!["Entries to purge:".to_string()];
    for item in items {
        let value = format!(
            "{} {} (approved: {})",
            item.member_handle,
            layout::format_kid_display_text(item.kid, KidDisplayFallback::Sanitized),
            item.approved_at
        );
        lines.extend(layout::format_value_lines("  ", &value));
    }
    lines.push(String::new());
    lines.push(format!("{} entry(ies) will be removed", items.len()));
    lines
}

pub(crate) fn print_recipient_set_purge_candidates(items: &[RecipientSetListItemView<'_>]) {
    layout::print_lines(
        format_recipient_set_purge_candidate_lines(items),
        LineTarget::Stderr,
    );
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

pub(crate) fn print_trust_purge_resigned() {
    eprintln!("The trust store signature was moved to the current signing key");
}

pub(crate) fn print_trust_purge_reset_to_empty() {
    eprintln!("Trust store was reset, so there were no known keys left to purge");
}

pub(crate) fn print_recipient_set_purge_reset_to_empty() {
    eprintln!("Trust store was reset, so there were no recipient sets left to purge");
}

#[cfg(test)]
#[path = "../../../../../tests/unit/internal/cli_common_output_text_trust_test.rs"]
mod tests;
