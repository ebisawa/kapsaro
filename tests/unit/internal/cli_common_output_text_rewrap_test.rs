// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::format_rewrap_batch_outcome_lines;
use crate::cli::common::output::rewrap::{RewrapBatchView, RewrapFailureView};
use crate::cli::common::output::text::layout::visible_width;

#[test]
fn test_format_rewrap_batch_outcome_lines_wraps_long_paths_and_errors() {
    let processed_path = format!(
        "secrets/{}/rotated-secret.file.enc",
        "very-long-directory-name/".repeat(5)
    );
    let failed_path = format!(
        "secrets/{}/failed-secret.file.enc",
        "another-very-long-directory-name/".repeat(5)
    );
    let error = format!(
        "signature verification failed after {}",
        "checking every candidate recipient key ".repeat(4)
    );
    let view = RewrapBatchView {
        processed_files: vec![processed_path],
        failed_files: vec![RewrapFailureView {
            path: failed_path,
            error,
        }],
    };

    let lines = format_rewrap_batch_outcome_lines(&view);

    assert_line_lengths_at_most(&lines, 100);
    assert!(lines.iter().any(|line| line.starts_with("Rewrapped: ")));
    assert!(lines
        .iter()
        .any(|line| line.starts_with("Error processing ")));
    assert!(lines
        .iter()
        .any(|line| line == "Rewrapped 1 file(s) successfully, 1 error(s)"));
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
