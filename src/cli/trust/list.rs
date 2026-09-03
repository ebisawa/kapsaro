// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! trust list CLI handler.

use crate::cli::common::command::build_cli_missing_member_handle_error;
use crate::cli::common::context::CliContext;
use crate::cli::common::output::trust::{print_recipient_set_list, print_trust_list};
use crate::cli::common::trust::run_with_trust_list_reset_recovery;
use kapsaro_core::api::trust::list::{
    list_known_keys_command, list_recipient_sets_command, resolve_trust_list_command,
};
use kapsaro_core::Error;

use super::ListArgs;

pub(crate) fn run_keys(args: ListArgs) -> Result<(), Error> {
    let context = CliContext::resolve(&args.common)?;
    let owner = require_owner(&context, args.member.member_handle)?;
    let command = resolve_trust_list_command(context.local_state()?, owner)?;
    let result =
        run_with_trust_list_reset_recovery(&command, || list_known_keys_command(&command))?;
    print_trust_list(args.common.json.json, &result)
}

pub(crate) fn run_recipients(args: ListArgs) -> Result<(), Error> {
    let context = CliContext::resolve(&args.common)?;
    let owner = require_owner(&context, args.member.member_handle)?;
    let command = resolve_trust_list_command(context.local_state()?, owner)?;
    let result =
        run_with_trust_list_reset_recovery(&command, || list_recipient_sets_command(&command))?;
    print_recipient_set_list(args.common.json.json, &result)
}

fn require_owner(
    context: &CliContext,
    explicit: Option<String>,
) -> Result<kapsaro_core::api::key::MemberHandle, Error> {
    context
        .member_handle(explicit)?
        .ok_or_else(|| build_cli_missing_member_handle_error(false))?
        .try_into()
}
