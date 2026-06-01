// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Rewrap command output helpers.

use crate::cli::common::output::json::rewrap::print_rewrap_batch_outcome as print_rewrap_batch_json;
use crate::cli::common::output::print_json_or_text;
use crate::cli::common::output::text::rewrap::print_rewrap_batch_outcome as print_rewrap_batch_text;
use kapsaro_core::cli_api::app::rewrap::types::RewrapBatchOutcome;
use kapsaro_core::cli_api::presentation::path::format_path_relative_to_cwd;
use kapsaro_core::{Error, Result};

pub(crate) struct RewrapFailureView {
    pub(crate) path: String,
    pub(crate) error: String,
}

pub(crate) struct RewrapBatchView {
    pub(crate) processed_files: Vec<String>,
    pub(crate) failed_files: Vec<RewrapFailureView>,
}

pub(crate) fn print_rewrap_batch_outcome(
    outcome: &RewrapBatchOutcome,
    json_output: bool,
    quiet: bool,
) -> Result<()> {
    let view = RewrapBatchView {
        processed_files: outcome
            .processed_files
            .iter()
            .map(|file| format_path_relative_to_cwd(&file.output_path))
            .collect(),
        failed_files: outcome
            .failed_files
            .iter()
            .map(|file| RewrapFailureView {
                path: format_path_relative_to_cwd(&file.output_path),
                error: file.error_message.clone(),
            })
            .collect(),
    };
    print_json_or_text(
        json_output,
        || print_rewrap_batch_json(&view),
        || {
            if !quiet || !view.failed_files.is_empty() {
                print_rewrap_batch_text(&view);
            }
        },
    )?;

    if !view.failed_files.is_empty() {
        return Err(Error::build_config_error(format!(
            "Failed to rewrap {} file(s). See errors above.",
            view.failed_files.len()
        )));
    }

    Ok(())
}
