// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{format_created_workspace_summary_lines, format_init_noop_summary_lines};
use crate::cli::common::output::text::layout::visible_width;
use std::path::PathBuf;

#[test]
fn test_format_created_workspace_summary_lines_wraps_long_workspace_path() {
    let workspace_path = long_workspace_path();

    let lines = format_created_workspace_summary_lines(&workspace_path);

    assert_line_lengths_at_most(&lines, 100);
    assert!(lines[0].starts_with("Creating workspace "));
}

#[test]
fn test_format_init_noop_summary_lines_wraps_long_workspace_path() {
    let workspace_path = long_workspace_path();

    let lines = format_init_noop_summary_lines(&workspace_path);

    assert_line_lengths_at_most(&lines, 100);
    assert!(lines[0].starts_with("Workspace already initialized at "));
    assert!(lines
        .iter()
        .any(|line| line.contains("only bootstraps a new workspace")));
}

fn long_workspace_path() -> PathBuf {
    PathBuf::from(format!(
        "target/{}/.secretenv",
        "very-long-workspace-directory-name/".repeat(6)
    ))
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
