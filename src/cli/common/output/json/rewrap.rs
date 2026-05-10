// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! JSON renderers for rewrap commands.

use crate::cli::common::output::json::print_json_output;
use crate::cli::common::output::rewrap::RewrapBatchView;
use crate::Result;
use serde::Serialize;

#[derive(Serialize)]
struct RewrapBatchResultOutput {
    success: bool,
    processed_files: Vec<String>,
    failed_files: Vec<RewrapBatchFailureOutput>,
}

#[derive(Serialize)]
struct RewrapBatchFailureOutput {
    path: String,
    error: String,
}

pub(crate) fn print_rewrap_batch_outcome(outcome: &RewrapBatchView) -> Result<()> {
    let output = build_rewrap_batch_result_output(outcome);
    print_json_output(&output)
}

fn build_rewrap_batch_result_output(outcome: &RewrapBatchView) -> RewrapBatchResultOutput {
    RewrapBatchResultOutput {
        success: outcome.failed_files.is_empty(),
        processed_files: outcome.processed_files.clone(),
        failed_files: outcome
            .failed_files
            .iter()
            .map(|file| RewrapBatchFailureOutput {
                path: file.path.clone(),
                error: file.error.clone(),
            })
            .collect(),
    }
}

#[cfg(test)]
#[path = "../../../../../tests/unit/internal/cli_common_output_json_rewrap_test.rs"]
mod tests;
