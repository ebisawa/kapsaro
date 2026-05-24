// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{
    format_known_key_list_lines, format_recipient_set_list_lines,
    format_trust_purge_candidate_lines,
};
use crate::cli::common::output::text::layout::visible_width;
use crate::cli::common::output::trust::view::{RecipientSetListItemView, TrustListItemView};

#[test]
fn test_format_known_key_list_lines_wraps_long_member_handles_and_kids() {
    let member_handle = format!("{}@example.com", "release.engineering.".repeat(4));
    let raw_kid = "invalid-kid-fragment".repeat(8);
    let item = TrustListItemView {
        kid: &raw_kid,
        member_handle: &member_handle,
        approved_at: "2026-05-01T00:00:00Z",
        approved_via: "manual-review",
    };

    let lines = format_known_key_list_lines(&[item]);

    assert_line_lengths_at_most(&lines, 100);
}

#[test]
fn test_format_recipient_set_list_lines_wraps_long_sid_hash_and_kids() {
    let sid = "sid-fragment".repeat(12);
    let recipient_set_hash = format!("sha256:{}", "abcdef0123456789".repeat(10));
    let recipient_kids = vec!["invalid-kid-fragment".repeat(8)];
    let item = RecipientSetListItemView {
        sid: &sid,
        recipient_kids: &recipient_kids,
        recipient_set_hash: &recipient_set_hash,
        approved_at: "2026-05-01T00:00:00Z",
        approved_via: "manual-review",
    };

    let lines = format_recipient_set_list_lines(&[item]);

    assert_line_lengths_at_most(&lines, 100);
}

#[test]
fn test_format_trust_purge_candidate_lines_wraps_long_values() {
    let member_handle = format!("{}@example.com", "release.engineering.".repeat(4));
    let raw_kid = "invalid-kid-fragment".repeat(8);
    let item = TrustListItemView {
        kid: &raw_kid,
        member_handle: &member_handle,
        approved_at: "2026-05-01T00:00:00Z",
        approved_via: "manual-review",
    };

    let lines = format_trust_purge_candidate_lines(&[item]);

    assert_line_lengths_at_most(&lines, 100);
}

fn assert_line_lengths_at_most(lines: &[String], max_width: usize) {
    for line in lines {
        assert!(
            visible_width(line) <= max_width,
            "expected line to fit within {max_width} columns, got {}: {line}",
            visible_width(line)
        );
    }
}
