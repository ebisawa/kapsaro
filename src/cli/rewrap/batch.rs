// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Batch rewrap execution over workspace files.

use super::promotion::{confirm_incoming_promotions, print_promotion_summary};
use super::RewrapArgs;
use crate::cli::common::command::resolve_options_with_allow_expired_key;
use crate::cli::common::output::rewrap::print_rewrap_batch_outcome;
use crate::cli::common::output::text::print_warnings;
use crate::cli::common::ssh::resolve_ssh_context_optional;
use crate::cli::common::trust::{
    confirm_non_member_acceptance, confirm_recipient_approvals, confirm_recipient_set_approval,
    confirm_signer_key_approval,
};
use secretenv_core::cli_api::app::rewrap::{execute_rewrap_batch_command, RewrapBatchCommandInput};
use secretenv_core::Result;

pub(crate) fn run_batch_rewrap(args: &RewrapArgs) -> Result<()> {
    let options = resolve_options_with_allow_expired_key(
        &args.common,
        args.allow_expired_key.allow_expired_key,
    )?;
    let ssh_ctx = resolve_ssh_context_optional(&options, args.member.member_handle.clone())?;
    let execution = secretenv_core::cli_api::app::context::execution::resolve_write_execution(
        &options,
        args.member.member_handle.clone(),
        ssh_ctx,
    )?;
    let outcome = execute_rewrap_batch_command(
        RewrapBatchCommandInput {
            options,
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
