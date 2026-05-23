// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! trust purge CLI handler.

use std::collections::BTreeSet;

use crate::cli::common::command::{
    resolve_options, resolve_trust_store_owner_member, resolve_write_execution_input,
};
use crate::cli::common::output::text::trust::print_purge_cancelled;
use crate::cli::common::output::trust::{
    print_recipient_set_purge_outcome, print_recipient_set_purge_preview,
    print_trust_purge_outcome, print_trust_purge_preview,
};
use crate::cli::common::prompt::confirm_destructive_action_or_cancel;
use crate::cli::common::trust::run_with_trust_store_reset_recovery;
use secretenv_core::cli_api::app::context::execution::ExecutionContext;
use secretenv_core::cli_api::app::context::options::CommonCommandOptions;
use secretenv_core::cli_api::app::trust::management::{
    execute_purge, execute_recipient_set_purge, list_purge_candidates,
    list_recipient_set_purge_candidates,
};
use secretenv_core::Error;
use time::OffsetDateTime;

use super::PurgeArgs;

pub(crate) fn run_keys(args: PurgeArgs) -> Result<(), Error> {
    run_purge_flow(
        args,
        list_purge_candidates,
        print_trust_purge_preview,
        execute_purge,
        print_trust_purge_outcome,
    )
}

pub(crate) fn run_recipients(args: PurgeArgs) -> Result<(), Error> {
    run_purge_flow(
        args,
        list_recipient_set_purge_candidates,
        print_recipient_set_purge_preview,
        execute_recipient_set_purge,
        print_recipient_set_purge_outcome,
    )
}

fn run_purge_flow<Candidates, Outcome, List, Preview, Execute, Print>(
    args: PurgeArgs,
    list_candidates: List,
    print_preview: Preview,
    execute: Execute,
    print_outcome: Print,
) -> Result<(), Error>
where
    List: Fn(&CommonCommandOptions, &str, OffsetDateTime) -> Result<Candidates, Error>,
    Preview: Fn(&Candidates, &mut BTreeSet<String>) -> bool,
    Execute: Fn(
        &CommonCommandOptions,
        &ExecutionContext,
        OffsetDateTime,
        bool,
    ) -> Result<Outcome, Error>,
    Print: Fn(&Outcome, &mut BTreeSet<String>),
{
    let older_than_timestamp = parse_duration_to_threshold(&args.older_than)?;
    let options = resolve_options(&args.common);
    let member_handle = args.member.member_handle.clone();
    let execution = resolve_write_execution_input(&options, member_handle.clone())?;
    let candidates = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, member_handle.clone()),
        || list_candidates(&options, &execution.member_handle, older_than_timestamp),
    )?;
    let mut shown_warnings = BTreeSet::new();
    if !print_preview(&candidates, &mut shown_warnings) {
        return Ok(());
    }

    if !confirm_purge_when_needed(args.force.force)? {
        print_purge_cancelled();
        return Ok(());
    }

    let result = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, member_handle.clone()),
        || execute(&options, &execution, older_than_timestamp, options.debug),
    )?;
    print_outcome(&result, &mut shown_warnings);
    Ok(())
}

/// Parse duration string (e.g. "180d") to a UTC threshold timestamp.
fn parse_duration_to_threshold(duration: &str) -> secretenv_core::Result<OffsetDateTime> {
    let days = parse_days(duration)?;
    Ok(time::OffsetDateTime::now_utc() - time::Duration::days(days))
}

fn parse_days(duration: &str) -> secretenv_core::Result<i64> {
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
