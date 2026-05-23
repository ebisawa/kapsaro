// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Batch rewrap execution over workspace files.

use super::promotion::{confirm_incoming_promotions, print_promotion_summary};
use super::RewrapArgs;
use crate::cli::common::command::resolve_write_execution_input;
use crate::cli::common::output::rewrap::print_rewrap_batch_outcome;
use crate::cli::common::output::text::print_warnings;
use crate::cli::common::trust::{
    confirm_non_member_acceptance, confirm_recipient_approvals, confirm_recipient_set_approval,
    confirm_signer_key_approval,
};
use secretenv_core::cli_api::app::context::options::CommonCommandOptions;
use secretenv_core::cli_api::app::rewrap::{execute_rewrap_batch_command, RewrapBatchCommandInput};
use secretenv_core::Result;

pub(crate) fn run_batch_rewrap(args: &RewrapArgs, options: &CommonCommandOptions) -> Result<()> {
    let execution = resolve_write_execution_input(options, args.member.member_handle.clone())?;
    let outcome = execute_rewrap_batch_command(
        RewrapBatchCommandInput {
            options: options.clone(),
            execution,
            rotate_key: args.rotate_key,
            clear_disclosure_history: args.clear_disclosure_history,
            explicit_targets: args.targets.clone(),
        },
        print_warnings,
        confirm_incoming_promotions,
        confirm_signer_key_approval,
        |candidate, context_label, current_recipients| {
            confirm_non_member_acceptance(candidate, context_label, current_recipients)
        },
        confirm_recipient_approvals,
        confirm_recipient_set_approval,
    )?;
    print_promotion_summary(&outcome.promoted_member_handles, args.common.quiet.quiet);
    print_rewrap_batch_outcome(&outcome, args.common.json.json, args.common.quiet.quiet)
}
