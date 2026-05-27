// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::format_rewrap_batch_outcome_lines;
use crate::cli::common::output::rewrap::{RewrapBatchView, RewrapFailureView};

#[test]
fn test_format_rewrap_batch_outcome_lines_keeps_long_paths_and_errors_inline() {
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
    let rendered = lines.join("\n");

    assert!(rendered.contains("very-long-directory-name"));
    assert!(rendered.contains("another-very-long-directory-name"));
    assert!(rendered.contains("checking every candidate recipient key"));
    assert!(lines.iter().any(|line| line.starts_with("Rewrapped: ")));
    assert!(lines
        .iter()
        .any(|line| line.starts_with("Error processing ")));
    assert!(lines
        .iter()
        .any(|line| line == "Rewrapped 1 file(s) successfully, 1 error(s)"));
}
