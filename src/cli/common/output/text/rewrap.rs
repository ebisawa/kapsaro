// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderers for rewrap commands.

use crate::cli::common::output::rewrap::RewrapBatchView;
use crate::cli::common::output::text::layout;
use crate::cli::error::format_stderr_error_message;

pub(crate) fn print_rewrap_batch_outcome(outcome: &RewrapBatchView) {
    for line in format_rewrap_batch_outcome_lines(outcome) {
        eprintln!("{line}");
    }
}

fn format_rewrap_batch_outcome_lines(outcome: &RewrapBatchView) -> Vec<String> {
    let mut lines = Vec::new();
    for file in &outcome.processed_files {
        lines.extend(layout::format_value_lines("Rewrapped: ", file));
    }
    for file in &outcome.failed_files {
        lines.extend(format_rewrap_failure_lines(file));
    }
    lines.push(String::new());
    lines.push(format!(
        "Rewrapped {} file(s) successfully, {} error(s)",
        outcome.processed_files.len(),
        outcome.failed_files.len()
    ));
    lines
}

fn format_rewrap_failure_lines(
    file: &crate::cli::common::output::rewrap::RewrapFailureView,
) -> Vec<String> {
    layout::format_value_lines(
        "Error processing ",
        &format!("{}: {}", file.path, file.error),
    )
    .into_iter()
    .map(|line| format_stderr_error_message(&line))
    .collect()
}

#[cfg(test)]
#[path = "../../../../../tests/unit/internal/cli_common_output_text_rewrap_test.rs"]
mod tests;
