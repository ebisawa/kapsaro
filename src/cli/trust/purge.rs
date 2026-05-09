// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! trust purge CLI handler.

use std::collections::BTreeSet;

use crate::app::trust::management::{
    execute_purge, execute_recipient_set_purge, list_purge_candidates,
    list_recipient_set_purge_candidates,
};
use crate::cli::common::command::{
    resolve_execution_input, resolve_options, resolve_trust_store_owner_member,
};
use crate::cli::common::output::text::trust::print_purge_cancelled;
use crate::cli::common::output::trust::{
    print_recipient_set_purge_outcome, print_recipient_set_purge_preview,
    print_trust_purge_outcome, print_trust_purge_preview,
};
use crate::cli::common::prompt::prompt_yes_no;
use crate::cli::common::trust::run_with_trust_store_reset_recovery;
use crate::support::tty;
use crate::Error;
use time::OffsetDateTime;

use super::PurgeArgs;

pub(crate) fn run_keys(args: PurgeArgs) -> Result<(), Error> {
    let older_than_timestamp = parse_duration_to_threshold(&args.older_than)?;
    let options = resolve_options(&args.common);
    let member_handle = args.member.member_handle.clone();
    let (_, execution) = resolve_execution_input(&args.common, member_handle.clone())?;
    let candidates = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, member_handle.clone()),
        || list_purge_candidates(&options, &execution.member_handle, older_than_timestamp),
    )?;
    let mut shown_warnings = BTreeSet::new();
    if !print_trust_purge_preview(&candidates, &mut shown_warnings) {
        return Ok(());
    }

    if !args.force.force {
        if !tty::is_interactive() {
            return Err(Error::InvalidOperation {
                message: "Non-interactive mode requires --force flag for purge".to_string(),
            });
        }
        if !confirm_purge()? {
            print_purge_cancelled();
            return Ok(());
        }
    }

    let result = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, member_handle.clone()),
        || execute_purge(&options, &execution, older_than_timestamp, options.debug),
    )?;
    print_trust_purge_outcome(&result, &mut shown_warnings);
    Ok(())
}

pub(crate) fn run_recipients(args: PurgeArgs) -> Result<(), Error> {
    let older_than_timestamp = parse_duration_to_threshold(&args.older_than)?;
    let options = resolve_options(&args.common);
    let member_handle = args.member.member_handle.clone();
    let (_, execution) = resolve_execution_input(&args.common, member_handle.clone())?;
    let candidates = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, member_handle.clone()),
        || {
            list_recipient_set_purge_candidates(
                &options,
                &execution.member_handle,
                older_than_timestamp,
            )
        },
    )?;
    let mut shown_warnings = BTreeSet::new();
    if !print_recipient_set_purge_preview(&candidates, &mut shown_warnings) {
        return Ok(());
    }

    if !args.force.force {
        if !tty::is_interactive() {
            return Err(Error::InvalidOperation {
                message: "Non-interactive mode requires --force flag for purge".to_string(),
            });
        }
        if !confirm_purge()? {
            print_purge_cancelled();
            return Ok(());
        }
    }

    let result = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, member_handle.clone()),
        || execute_recipient_set_purge(&options, &execution, older_than_timestamp, options.debug),
    )?;
    print_recipient_set_purge_outcome(&result, &mut shown_warnings);
    Ok(())
}

/// Parse duration string (e.g. "180d") to a UTC threshold timestamp.
fn parse_duration_to_threshold(duration: &str) -> crate::Result<OffsetDateTime> {
    let days = parse_days(duration)?;
    Ok(time::OffsetDateTime::now_utc() - time::Duration::days(days))
}

fn parse_days(duration: &str) -> crate::Result<i64> {
    let s = duration.trim();
    if let Some(num_str) = s.strip_suffix('d') {
        let days = num_str
            .parse::<i64>()
            .map_err(|_| Error::InvalidOperation {
                message: format!("Invalid duration: '{}'", duration),
            })?;
        if days <= 0 {
            return Err(Error::InvalidOperation {
                message: format!("Duration must be positive, got: '{}'", duration),
            });
        }
        Ok(days)
    } else {
        Err(Error::InvalidOperation {
            message: format!(
                "Duration must be in days (e.g. '180d'), got: '{}'",
                duration
            ),
        })
    }
}

fn confirm_purge() -> crate::Result<bool> {
    prompt_yes_no("Proceed?", false)
}
