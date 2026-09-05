// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! trust purge CLI handler.

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
    run_with_trust_command_session_reset_without_retry, TrustStoreResetOutcome,
};
use kapsaro_core::api::key::parse_relative_duration_days;
use kapsaro_core::api::trust::management::{
    execute_purge, execute_recipient_set_purge, list_purge_candidates,
    list_recipient_set_purge_candidates, ReviewedPurgeCandidates,
};
use kapsaro_core::api::trust::TrustCommandSession;
use kapsaro_core::Error;
use time::OffsetDateTime;

use super::{load_trust_session, PurgeArgs};

pub(crate) fn run_keys(args: PurgeArgs) -> Result<(), Error> {
    run_purge(
        args,
        list_purge_candidates,
        print_trust_purge_preview,
        execute_purge,
        print_trust_purge_reset_to_empty,
        print_trust_purge_outcome,
    )
}

pub(crate) fn run_recipients(args: PurgeArgs) -> Result<(), Error> {
    run_purge(
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
/// keys and recipient sets share one path without a marker type per variant.
fn run_purge<Item, Outcome>(
    args: PurgeArgs,
    list: for<'a> fn(
        &'a TrustCommandSession,
        OffsetDateTime,
    ) -> Result<ReviewedPurgeCandidates<'a, Item>, Error>,
    // Shows the candidates and reports whether the purge should continue.
    preview: for<'a> fn(&ReviewedPurgeCandidates<'a, Item>) -> bool,
    execute: for<'a> fn(&ReviewedPurgeCandidates<'a, Item>) -> Result<Outcome, Error>,
    // Reports that a trust store reset left nothing to purge.
    //
    // A purge count is the wrong thing to print here: the store was discarded
    // whole, so "0 removed" reads as "nothing happened" when in fact every
    // approval is gone.
    report_reset_to_empty: impl Fn(),
    report: impl Fn(&Outcome),
) -> Result<(), Error> {
    let older_than = parse_duration_to_threshold(&args.older_than)?;
    let session = load_trust_session(&args.common, args.member.member_handle.clone())?;

    let listed = run_with_trust_command_session_reset_without_retry(&session, || {
        list(&session, older_than)
    })?;
    let TrustStoreResetOutcome::Completed(candidates) = listed else {
        report_reset_to_empty();
        return Ok(());
    };
    if !preview(&candidates) {
        return Ok(());
    }
    purge_reviewed_candidates(&candidates, args.force.force, execute, report)
}

/// Confirm the candidates that were just shown, then remove exactly those.
///
/// The write-back is bound to the candidates that were just shown, so it
/// reports a store that moved as a conflict and never asks to delete one.
fn purge_reviewed_candidates<Item, Outcome>(
    candidates: &ReviewedPurgeCandidates<'_, Item>,
    force: bool,
    execute: for<'a> fn(&ReviewedPurgeCandidates<'a, Item>) -> Result<Outcome, Error>,
    report: impl Fn(&Outcome),
) -> Result<(), Error> {
    if !confirm_purge_when_needed(force)? {
        print_purge_cancelled();
        return Ok(());
    }
    report(&execute(candidates)?);
    Ok(())
}

/// Turn a relative duration such as "180d" into the UTC threshold to purge from.
///
/// The parser only returns a positive day count that fits a `time::Duration`,
/// so the threshold is always in the past. A span that reaches back past the
/// earliest representable date is refused rather than left to overflow.
fn parse_duration_to_threshold(duration: &str) -> kapsaro_core::Result<OffsetDateTime> {
    let days = parse_relative_duration_days(duration)?;
    time::OffsetDateTime::now_utc()
        .checked_sub(time::Duration::days(days))
        .ok_or_else(|| {
            Error::build_parse_error(format!(
                "Duration is too large to reach a date in the past: {}",
                duration
            ))
        })
}

fn confirm_purge_when_needed(force: bool) -> Result<bool, Error> {
    confirm_destructive_action_or_cancel(force, "Proceed?", purge_non_interactive_error())
}

fn purge_non_interactive_error() -> String {
    "Non-interactive mode requires --force flag for purge".to_string()
}
