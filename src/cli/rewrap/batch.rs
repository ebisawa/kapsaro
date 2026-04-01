// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Batch rewrap execution over workspace files.

use super::promotion::{confirm_incoming_promotions, print_promotion_summary};
use super::RewrapArgs;
use crate::app::context::options::CommonCommandOptions;
use crate::app::rewrap::execution::execute_rewrap_batch;
use crate::app::rewrap::plan::build_rewrap_batch_plan;
use crate::app::rewrap::types::{RewrapBatchOutcome, RewrapBatchRequest};
use crate::cli::common::output::json;
use crate::cli::common::ssh::resolve_ssh_context_optional;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use std::io::IsTerminal;

pub(crate) fn execute_batch_rewrap(args: &RewrapArgs) -> Result<()> {
    let options = CommonCommandOptions::from(&args.common);
    let ssh_ctx = resolve_ssh_context_optional(&options, args.member_id.clone())?;
    let plan = build_rewrap_batch_plan(&options)?;

    let accepted_ids = if let Some(report) = plan.incoming_report.as_ref() {
        let is_interactive = std::io::stdin().is_terminal();
        let accepted =
            confirm_incoming_promotions(report, is_interactive, &mut std::io::stdin().lock())?;
        print_promotion_summary(report, &accepted, args.common.quiet);
        accepted
    } else {
        Vec::new()
    };

    let request = RewrapBatchRequest {
        options,
        member_id: args.member_id.clone(),
        rotate_key: args.rotate_key,
        clear_disclosure_history: args.clear_disclosure_history,
        accepted_promotions: accepted_ids,
    };
    let outcome = execute_rewrap_batch(&request, &plan, ssh_ctx)?;
    print_batch_result(&outcome, args.common.json, args.common.quiet)
}

fn print_batch_result(outcome: &RewrapBatchOutcome, json_output: bool, quiet: bool) -> Result<()> {
    if json_output {
        return print_json_batch_result(outcome);
    }
    if !quiet {
        print_text_batch_result(outcome);
    }
    check_batch_errors(outcome)
}

fn print_json_batch_result(outcome: &RewrapBatchOutcome) -> Result<()> {
    let processed: Vec<String> = outcome
        .processed_files
        .iter()
        .map(|file| display_path_relative_to_cwd(&file.output_path))
        .collect();
    let failed: Vec<serde_json::Value> = outcome
        .failed_files
        .iter()
        .map(|file| {
            serde_json::json!({
                "path": display_path_relative_to_cwd(&file.output_path),
                "error": file.error_message,
            })
        })
        .collect();
    json::print_json_output(&serde_json::json!({
        "success": outcome.failed_files.is_empty(),
        "processed_files": processed,
        "failed_files": failed,
    }))
}

fn print_text_batch_result(outcome: &RewrapBatchOutcome) {
    for file in &outcome.processed_files {
        eprintln!(
            "Rewrapped: {}",
            display_path_relative_to_cwd(&file.output_path)
        );
    }
    for file in &outcome.failed_files {
        eprintln!(
            "Error processing {}: {}",
            display_path_relative_to_cwd(&file.output_path),
            file.error_message
        );
    }
    eprintln!(
        "\nRewraped {} file(s) successfully, {} error(s)",
        outcome.processed_files.len(),
        outcome.failed_files.len()
    );
}

fn check_batch_errors(outcome: &RewrapBatchOutcome) -> Result<()> {
    if !outcome.failed_files.is_empty() {
        return Err(Error::Config {
            message: format!(
                "Failed to rewrap {} file(s). See errors above.",
                outcome.failed_files.len()
            ),
        });
    }
    Ok(())
}
