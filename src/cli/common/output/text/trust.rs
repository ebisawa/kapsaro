// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderers for trust commands.

use crate::cli::common::output::trust::{RecipientSetListItemView, TrustListItemView};
use secretenv_core::cli_api::presentation::kid::format_kid_display_lossy;

pub(crate) fn print_known_key_list(items: &[TrustListItemView<'_>]) {
    for item in items {
        let kid_display = format_kid_display_lossy(item.kid);
        eprintln!(
            "  {} {} (approved: {}, via: {})",
            item.member_handle, kid_display, item.approved_at, item.approved_via
        );
    }
    eprintln!("\n{} known key(s)", items.len());
}

pub(crate) fn print_empty_known_key_list() {
    eprintln!("No known keys in trust store");
}

pub(crate) fn print_recipient_set_list(items: &[RecipientSetListItemView<'_>]) {
    for item in items {
        eprintln!(
            "  {} (approved: {}, via: {})",
            item.sid, item.approved_at, item.approved_via
        );
        eprintln!("    hash: {}", item.recipient_set_hash);
        eprintln!("    recipient kids:");
        for kid in item.recipient_kids {
            eprintln!("      - {}", format_kid_display_lossy(kid));
        }
    }
    eprintln!("\n{} recipient set(s)", items.len());
}

pub(crate) fn print_empty_recipient_set_list() {
    eprintln!("No recipient sets in trust store");
}

pub(crate) fn print_trust_remove_summary(kid: &str, member_handle: &str) {
    let kid_display = format_kid_display_lossy(kid);
    eprintln!(
        "Removed kid '{}' (member: {}) from trust store",
        kid_display, member_handle
    );
}

pub(crate) fn print_recipient_set_remove_summary(sid: &str) {
    eprintln!("Removed recipient set '{}' from trust store", sid);
}

pub(crate) fn print_no_entries_to_purge() {
    eprintln!("No entries to purge");
}

pub(crate) fn print_trust_purge_candidates(items: &[TrustListItemView<'_>]) {
    eprintln!("Entries to purge:");
    for item in items {
        let kid_display = format_kid_display_lossy(item.kid);
        eprintln!(
            "  {} {} (approved: {})",
            item.member_handle, kid_display, item.approved_at
        );
    }
    eprintln!("\n{} entry(ies) will be removed", items.len());
}

pub(crate) fn print_recipient_set_purge_candidates(items: &[RecipientSetListItemView<'_>]) {
    eprintln!("Recipient sets to purge:");
    for item in items {
        eprintln!("  {} (approved: {})", item.sid, item.approved_at);
    }
    eprintln!("\n{} recipient set(s) will be removed", items.len());
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
