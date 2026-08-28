// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! trust remove CLI handler.

use crate::cli::common::command::{resolve_options, resolve_write_execution_input};
use crate::cli::common::output::text::trust::{
    print_key_removed_by_reset, print_recipient_set_remove_summary,
    print_recipient_set_removed_by_reset, print_trust_remove_summary,
};
use crate::cli::common::trust::{
    run_with_execution_trust_store_reset_without_retry, TrustStoreResetOutcome,
};
use kapsaro_core::cli_api::app::trust::management::{
    remove_known_key_command, remove_recipient_set_command,
};
use kapsaro_core::Error;

use super::{RecipientRemoveArgs, RemoveArgs};

pub(crate) fn run_key(args: RemoveArgs) -> Result<(), Error> {
    let options = resolve_options(&args.common);
    let member_handle = args.member.member_handle.clone();
    let execution = resolve_write_execution_input(&options, member_handle)?;
    let removed = run_with_execution_trust_store_reset_without_retry(&execution, || {
        remove_known_key_command(&options, &execution, &args.kid)
    })?;
    match removed {
        TrustStoreResetOutcome::Completed(result) => {
            print_trust_remove_summary(&result.kid, &result.member_handle);
        }
        TrustStoreResetOutcome::ResetToEmpty => print_key_removed_by_reset(),
    }
    Ok(())
}

pub(crate) fn run_recipient(args: RecipientRemoveArgs) -> Result<(), Error> {
    let options = resolve_options(&args.common);
    let member_handle = args.member.member_handle.clone();
    let execution = resolve_write_execution_input(&options, member_handle)?;
    let removed = run_with_execution_trust_store_reset_without_retry(&execution, || {
        remove_recipient_set_command(&options, &execution, &args.sid)
    })?;
    match removed {
        TrustStoreResetOutcome::Completed(sid) => print_recipient_set_remove_summary(&sid),
        TrustStoreResetOutcome::ResetToEmpty => print_recipient_set_removed_by_reset(),
    }
    Ok(())
}
