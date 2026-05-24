// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{capped_pair_left_width, format_pair_row, visible_width, TEXT_WIDTH};

#[test]
fn test_format_pair_row_keeps_short_pair_inline() {
    let lines = format_pair_row("  ", "alice@example.com", "KAD1-AAAA", 17);

    assert_eq!(lines, vec!["  alice@example.com  KAD1-AAAA"]);
}

#[test]
fn test_format_pair_row_wraps_pair_over_text_width() {
    let left = "avery.long.member.handle.for.release.engineering@example.com";
    let right = "KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD";

    let lines = format_pair_row("  ", left, right, left.len());

    assert_eq!(lines, vec![format!("  {left}"), format!("    {right}")]);
    assert!(lines.iter().all(|line| visible_width(line) <= TEXT_WIDTH));
}

#[test]
fn test_capped_pair_left_width_preserves_text_width_budget() {
    let left_width = capped_pair_left_width(80, "  ", 39);

    assert_eq!(left_width, 57);
}
