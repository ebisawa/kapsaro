// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::format_kv_key_list_lines;
use crate::cli::common::output::kv::view::KvKeyView;
use crate::cli::common::output::text::layout::visible_width;

#[test]
fn test_format_kv_key_list_lines_wraps_long_disclosed_key() {
    let key = format!("SECRET_{}", "VERY_LONG_NAME_".repeat(12));
    let keys = [KvKeyView {
        key: &key,
        disclosed: true,
    }];

    let lines = format_kv_key_list_lines(&keys);

    assert_line_lengths_at_most(&lines, 100);
    assert!(lines.iter().any(|line| line.contains("[DISCLOSED]")));
}

#[test]
fn test_format_kv_key_list_lines_wraps_long_plain_key() {
    let key = format!("SECRET_{}", "VERY_LONG_NAME_".repeat(12));
    let keys = [KvKeyView {
        key: &key,
        disclosed: false,
    }];

    let lines = format_kv_key_list_lines(&keys);

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
