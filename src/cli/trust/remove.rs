// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! trust remove CLI handler.

use crate::cli::common::output::text::trust::{
    print_key_removed_by_reset, print_recipient_set_remove_summary,
    print_recipient_set_removed_by_reset, print_trust_remove_summary,
};
use crate::cli::common::trust::{
    run_with_trust_command_session_reset_without_retry, TrustStoreResetOutcome,
};
use kapsaro_core::api::trust::management::{
    remove_known_key_command, remove_recipient_set_command,
};
use kapsaro_core::Error;

use super::{load_trust_session, RecipientRemoveArgs, RemoveArgs};

pub(crate) fn run_key(args: RemoveArgs) -> Result<(), Error> {
    let session = load_trust_session(&args.common, args.member.member_handle.clone())?;
    let removed = run_with_trust_command_session_reset_without_retry(&session, || {
        remove_known_key_command(&session, &args.kid)
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
    let session = load_trust_session(&args.common, args.member.member_handle.clone())?;
    let removed = run_with_trust_command_session_reset_without_retry(&session, || {
        remove_recipient_set_command(&session, &args.sid)
    })?;
    match removed {
        TrustStoreResetOutcome::Completed(sid) => print_recipient_set_remove_summary(&sid),
        TrustStoreResetOutcome::ResetToEmpty => print_recipient_set_removed_by_reset(),
    }
    Ok(())
}
