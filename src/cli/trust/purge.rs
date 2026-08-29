// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! trust purge CLI handler.

use crate::cli::common::command::{resolve_options, resolve_write_execution_input};
use crate::cli::common::output::text::trust::{
    print_purge_cancelled, print_recipient_set_purge_reset_to_empty,
    print_trust_purge_reset_to_empty,
};
use crate::cli::common::output::trust::{
    print_recipient_set_purge_outcome, print_recipient_set_purge_preview,
    print_trust_purge_outcome, print_trust_purge_preview,
};
use crate::cli::common::prompt::confirm_destructive_action_or_cancel;
use crate::cli::common::trust::{
    run_with_execution_trust_store_reset_without_retry, TrustStoreResetOutcome,
};
use kapsaro_core::cli_api::app::context::execution::ExecutionContext;
use kapsaro_core::cli_api::app::trust::management::{
    execute_purge, execute_recipient_set_purge, list_purge_candidates,
    list_recipient_set_purge_candidates, ReviewedPurgeCandidates,
};
use kapsaro_core::Error;
use time::OffsetDateTime;

use super::PurgeArgs;

pub(crate) fn run_keys(args: PurgeArgs) -> Result<(), Error> {
    run_purge_flow(
        args,
        list_purge_candidates,
        print_trust_purge_preview,
        execute_purge,
        print_trust_purge_reset_to_empty,
        print_trust_purge_outcome,
    )
}

pub(crate) fn run_recipients(args: PurgeArgs) -> Result<(), Error> {
    run_purge_flow(
        args,
        list_recipient_set_purge_candidates,
        print_recipient_set_purge_preview,
        execute_recipient_set_purge,
        print_recipient_set_purge_reset_to_empty,
        print_recipient_set_purge_outcome,
    )
}

/// Shared shape of a purge variant: how its entries are listed, previewed,
/// removed and reported. Taking the four steps as parameters lets both known
/// keys and recipient sets share this flow without a marker type per variant.
fn run_purge_flow<Item, Outcome>(
    args: PurgeArgs,
    list: impl Fn(&ExecutionContext, OffsetDateTime) -> Result<ReviewedPurgeCandidates<Item>, Error>,
    // Shows the candidates and reports whether the flow should continue.
    preview: impl Fn(&ReviewedPurgeCandidates<Item>) -> bool,
    execute: impl Fn(&ExecutionContext, &ReviewedPurgeCandidates<Item>) -> Result<Outcome, Error>,
    // Reports that a trust store reset left nothing to purge.
    //
    // A purge count is the wrong thing to print here: the store was discarded
    // whole, so "0 removed" reads as "nothing happened" when in fact every
    // approval is gone.
    report_reset_to_empty: impl Fn(),
    report: impl Fn(&Outcome),
) -> Result<(), Error> {
    let older_than = parse_duration_to_threshold(&args.older_than)?;
    let options = resolve_options(&args.common);
    let execution = resolve_write_execution_input(&options, args.member.member_handle.clone())?;

    let listed = run_with_execution_trust_store_reset_without_retry(&execution, || {
        list(&execution, older_than)
    })?;
    let candidates = match listed {
        TrustStoreResetOutcome::Completed(candidates) => candidates,
        TrustStoreResetOutcome::ResetToEmpty => {
            report_reset_to_empty();
            return Ok(());
        }
    };
    if !preview(&candidates) {
        return Ok(());
    }
    if !confirm_purge_when_needed(args.force.force)? {
        print_purge_cancelled();
        return Ok(());
    }

    // The write-back is bound to the candidates that were just shown, so it
    // reports a store that moved as a conflict and never asks to delete one.
    report(&execute(&execution, &candidates)?);
    Ok(())
}

/// Parse duration string (e.g. "180d") to a UTC threshold timestamp.
fn parse_duration_to_threshold(duration: &str) -> kapsaro_core::Result<OffsetDateTime> {
    let days = parse_days(duration)?;
    Ok(time::OffsetDateTime::now_utc() - time::Duration::days(days))
}

fn parse_days(duration: &str) -> kapsaro_core::Result<i64> {
    let s = duration.trim();
    if let Some(num_str) = s.strip_suffix('d') {
        let days = num_str.parse::<i64>().map_err(|_| {
            Error::build_invalid_operation_error(format!("Invalid duration: '{}'", duration))
        })?;
        if days <= 0 {
            return Err(Error::build_invalid_operation_error(format!(
                "Duration must be positive, got: '{}'",
                duration
            )));
        }
        Ok(days)
    } else {
        Err(Error::build_invalid_operation_error(format!(
            "Duration must be in days (e.g. '180d'), got: '{}'",
            duration
        )))
    }
}

fn confirm_purge_when_needed(force: bool) -> Result<bool, Error> {
    confirm_destructive_action_or_cancel(force, "Proceed?", purge_non_interactive_error())
}

fn purge_non_interactive_error() -> String {
    "Non-interactive mode requires --force flag for purge".to_string()
}
