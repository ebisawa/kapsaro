// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! JSON renderers for rewrap commands.

use crate::cli::common::output::json::print_json_output;
use crate::cli::common::output::rewrap::RewrapBatchView;
use secretenv_core::Result;
use serde::Serialize;

#[derive(Serialize)]
struct RewrapBatchResultOutput<'a> {
    success: bool,
    summary: RewrapBatchSummaryOutput<'a>,
}

#[derive(Serialize)]
struct RewrapBatchSummaryOutput<'a> {
    processed_files: Vec<&'a str>,
    failed_files: Vec<RewrapBatchFailureOutput<'a>>,
}

#[derive(Serialize)]
struct RewrapBatchFailureOutput<'a> {
    path: &'a str,
    error: &'a str,
}

pub(crate) fn print_rewrap_batch_outcome(outcome: &RewrapBatchView) -> Result<()> {
    let output = build_rewrap_batch_result_output(outcome);
    print_json_output(&output)
}

fn build_rewrap_batch_result_output(outcome: &RewrapBatchView) -> RewrapBatchResultOutput<'_> {
    RewrapBatchResultOutput {
        success: outcome.failed_files.is_empty(),
        summary: RewrapBatchSummaryOutput {
            processed_files: outcome.processed_files.iter().map(String::as_str).collect(),
            failed_files: outcome
                .failed_files
                .iter()
                .map(|file| RewrapBatchFailureOutput {
                    path: &file.path,
                    error: &file.error,
                })
                .collect(),
        },
    }
}

#[cfg(test)]
#[path = "../../../../../tests/unit/internal/cli_common_output_json_rewrap_test.rs"]
mod tests;
