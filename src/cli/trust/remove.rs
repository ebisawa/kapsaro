// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! trust remove CLI handler.

use crate::cli::common::command::{
    resolve_options, resolve_trust_store_owner_member, resolve_write_execution_input,
};
use crate::cli::common::output::text;
use crate::cli::common::output::text::trust::{
    print_recipient_set_remove_summary, print_trust_remove_summary,
};
use crate::cli::common::trust::run_with_trust_store_reset_recovery;
use secretenv_core::cli_api::app::trust::management::{
    remove_known_key_command, remove_recipient_set_command,
};
use secretenv_core::Error;

use super::{RecipientRemoveArgs, RemoveArgs};

pub(crate) fn run_key(args: RemoveArgs) -> Result<(), Error> {
    let options = resolve_options(&args.common);
    let member_handle = args.member.member_handle.clone();
    let result = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, member_handle.clone()),
        || {
            let execution = resolve_write_execution_input(&options, member_handle.clone())?;
            remove_known_key_command(&options, &execution, &args.kid, options.debug)
        },
    )?;
    text::print_warnings(&result.warnings);
    print_trust_remove_summary(&result.value.kid, &result.value.member_handle);
    Ok(())
}

pub(crate) fn run_recipient(args: RecipientRemoveArgs) -> Result<(), Error> {
    let options = resolve_options(&args.common);
    let member_handle = args.member.member_handle.clone();
    let result = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, member_handle.clone()),
        || {
            let execution = resolve_write_execution_input(&options, member_handle.clone())?;
            remove_recipient_set_command(&options, &execution, &args.sid, options.debug)
        },
    )?;
    text::print_warnings(&result.warnings);
    print_recipient_set_remove_summary(&result.value);
    Ok(())
}
