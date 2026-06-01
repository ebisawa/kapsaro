// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{format_diagnostic_lines, format_pair_row};

#[test]
fn test_format_pair_row_keeps_short_pair_inline() {
    let lines = format_pair_row("  ", "alice@example.com", "KAD1-AAAA", 17);

    assert_eq!(lines, vec!["  alice@example.com  KAD1-AAAA"]);
}

#[test]
fn test_format_pair_row_keeps_long_pair_inline() {
    let left = "avery.long.member.handle.for.release.engineering@example.com";
    let right = "KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD";

    let lines = format_pair_row("  ", left, right, left.len());

    assert_eq!(lines, vec![format!("  {left}  {right}")]);
}

#[test]
fn test_format_diagnostic_lines_keeps_long_message_inline() {
    let message = "Recipient kid is not active in this workspace. Run kapsaro rewrap before writing this artifact.";

    let lines = format_diagnostic_lines("Warning: ", message);

    assert_eq!(
        lines,
        vec![
            "Warning: Recipient kid is not active in this workspace. Run kapsaro rewrap before writing this artifact."
        ]
    );
}

#[test]
fn test_format_diagnostic_lines_keeps_explicit_detail_lines() {
    let message = "Recipient kid is not active.\nKid: KAD1-AAAA\nAction: Run kapsaro rewrap.";

    let lines = format_diagnostic_lines("Error: ", message);

    assert_eq!(
        lines,
        vec![
            "Error: Recipient kid is not active.",
            "       Kid: KAD1-AAAA",
            "       Action: Run kapsaro rewrap.",
        ]
    );
}
