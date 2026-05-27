// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::format_kv_key_list_lines;
use crate::cli::common::output::kv::view::KvKeyView;

#[test]
fn test_format_kv_key_list_lines_keeps_long_disclosed_key_inline() {
    let key = format!("SECRET_{}", "VERY_LONG_NAME_".repeat(12));
    let keys = [KvKeyView {
        key: &key,
        disclosed: true,
    }];

    let lines = format_kv_key_list_lines(&keys);

    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains(&key));
    assert!(lines.iter().any(|line| line.contains("[DISCLOSED]")));
}

#[test]
fn test_format_kv_key_list_lines_keeps_long_plain_key_inline() {
    let key = format!("SECRET_{}", "VERY_LONG_NAME_".repeat(12));
    let keys = [KvKeyView {
        key: &key,
        disclosed: false,
    }];

    let lines = format_kv_key_list_lines(&keys);

    assert_eq!(lines, vec![key]);
}
