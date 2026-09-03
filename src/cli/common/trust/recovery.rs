// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust store recovery for corrupted local trust cache files.
//!
//! Keeps reset planning, confirmation, and retry orchestration outside review prompts.

#[cfg(test)]
use std::io::BufRead;

use crate::cli::common::output::text::print_warning;
use crate::cli::common::presentation::format_path_relative_to_cwd;
use crate::cli::common::presentation::tty;
use crate::cli::common::prompt::prompt_yes_no;
#[cfg(test)]
use crate::cli::common::prompt::prompt_yes_no_with_reader;
use kapsaro_core::api::trust::list::TrustListCommand;
use kapsaro_core::api::trust::recovery::{
    build_trust_store_reset_plan_from_list_command, build_trust_store_reset_plan_from_session,
    classify_trust_store_reset, execute_trust_store_reset,
    observe_trust_store_recovery_from_list_command, observe_trust_store_recovery_from_session,
    TrustStoreRecoveryToken, TrustStoreResetCause, TrustStoreResetLoss, TrustStoreResetPlan,
};
use kapsaro_core::api::trust::{TrustCommandSession, WorkspaceReadSession};
use kapsaro_core::{Error, Result};

/// Retry one workspace read after resetting the exact trust store it observed.
pub(crate) fn run_with_workspace_read_trust_store_reset_recovery<T, Run>(
    session: &WorkspaceReadSession<'_>,
    run: Run,
) -> Result<T>
where
    Run: FnMut() -> Result<T>,
{
    let mut token = Some(session.observe_trust_store_recovery());
    run_with_trust_store_reset_retry(run, |error| {
        recover_invalid_trust_store_from_workspace_read(
            session,
            take_recovery_token(&mut token)?,
            error,
        )
    })
}

pub(crate) fn run_with_trust_list_reset_recovery<T, Run>(
    command: &TrustListCommand,
    run: Run,
) -> Result<T>
where
    Run: FnMut() -> Result<T>,
{
    let mut token = Some(observe_trust_store_recovery_from_list_command(command));
    run_with_trust_store_reset_retry(run, |error| {
        recover_invalid_trust_store_from_list_command(
            command,
            take_recovery_token(&mut token)?,
            error,
        )
    })
}

pub(crate) fn run_with_trust_command_session_reset_recovery<T, Run>(
    session: &TrustCommandSession,
    run: Run,
) -> Result<T>
where
    Run: FnMut() -> Result<T>,
{
    let mut token = Some(observe_trust_store_recovery_from_session(session));
    run_with_trust_store_reset_retry(run, |error| {
        recover_invalid_trust_store_from_session(session, take_recovery_token(&mut token)?, error)
    })
}

pub(crate) fn run_with_trust_command_session_reset_without_retry<T, Run>(
    session: &TrustCommandSession,
    run: Run,
) -> Result<TrustStoreResetOutcome<T>>
where
    Run: FnMut() -> Result<T>,
{
    let mut token = Some(observe_trust_store_recovery_from_session(session));
    run_with_trust_store_reset_without_retry(run, |error| {
        recover_invalid_trust_store_from_session(session, take_recovery_token(&mut token)?, error)
    })
}

/// Hand the one observation over to the one reset it can be spent on.
///
/// A command offers at most one reset, so the observation is taken out rather
/// than reused: a second offer would be bound to a store that the first reset
/// already deleted.
fn take_recovery_token(
    token: &mut Option<TrustStoreRecoveryToken>,
) -> Result<TrustStoreRecoveryToken> {
    token.take().ok_or_else(|| {
        Error::build_invalid_operation_error(
            "Local trust store reset was already offered for this command".to_string(),
        )
    })
}

pub(crate) enum TrustStoreResetOutcome<T> {
    Completed(T),
    ResetToEmpty,
}

fn run_with_trust_store_reset_retry<T, Run, Recover>(
    mut run: Run,
    mut recover: Recover,
) -> Result<T>
where
    Run: FnMut() -> Result<T>,
    Recover: FnMut(Error) -> Result<()>,
{
    let mut attempted_reset = false;
    loop {
        match run() {
            Ok(value) => return Ok(value),
            Err(error) if !attempted_reset => match classify_trust_store_reset(&error) {
                Some(_) => {
                    recover(error)?;
                    attempted_reset = true;
                }
                None => return Err(error),
            },
            Err(error) => return Err(error),
        }
    }
}

/// Run once, and on a trust-store recovery error let the operator confirm the
/// reset. Recovery deletes the store, so the reviewed state the operation was
/// bound to is gone: the caller reports an empty result instead of retrying.
fn run_with_trust_store_reset_without_retry<T, Run, Recover>(
    mut run: Run,
    mut recover: Recover,
) -> Result<TrustStoreResetOutcome<T>>
where
    Run: FnMut() -> Result<T>,
    Recover: FnMut(Error) -> Result<()>,
{
    match run() {
        Ok(value) => Ok(TrustStoreResetOutcome::Completed(value)),
        Err(error) => match classify_trust_store_reset(&error) {
            Some(_) => recover(error).map(|()| TrustStoreResetOutcome::ResetToEmpty),
            None => Err(error),
        },
    }
}

fn recover_invalid_trust_store_from_list_command(
    command: &TrustListCommand,
    token: TrustStoreRecoveryToken,
    error: Error,
) -> Result<()> {
    let plan = build_trust_store_reset_plan_from_list_command(
        command,
        token,
        error,
        tty::is_interactive(),
    )?;
    recover_prepared_trust_store(&plan, confirm_trust_store_reset)
}

fn recover_invalid_trust_store_from_session(
    session: &TrustCommandSession,
    token: TrustStoreRecoveryToken,
    error: Error,
) -> Result<()> {
    let plan =
        build_trust_store_reset_plan_from_session(session, token, error, tty::is_interactive())?;
    recover_prepared_trust_store(&plan, confirm_trust_store_reset)
}

fn recover_invalid_trust_store_from_workspace_read(
    session: &WorkspaceReadSession<'_>,
    token: TrustStoreRecoveryToken,
    error: Error,
) -> Result<()> {
    let plan = session.build_trust_store_reset_plan(token, error, tty::is_interactive())?;
    recover_prepared_trust_store(&plan, confirm_trust_store_reset)
}

fn recover_prepared_trust_store(
    plan: &TrustStoreResetPlan,
    confirm: impl FnOnce(&TrustStoreResetPlan) -> Result<bool>,
) -> Result<()> {
    print_warning(plan.warning_message());
    if !confirm(plan)? {
        return Err(Error::build_invalid_operation_error(
            "Local trust store reset was declined".to_string(),
        ));
    }

    let outcome = execute_trust_store_reset(plan)?;
    let path = format_path_relative_to_cwd(&outcome.path);
    if outcome.deleted {
        eprintln!("Deleted local trust store '{path}'. Continuing with an empty trust cache.");
    } else {
        eprintln!(
            "Local trust store '{path}' was already gone. Continuing with an empty trust cache."
        );
    }
    Ok(())
}

/// The question one plan asks, with everything the plan knows about the cost.
fn build_plan_reset_prompt(plan: &TrustStoreResetPlan) -> String {
    let recovery_hint = plan.recovery_hint();
    trust_store_reset_prompt(
        plan.path(),
        plan.cause(),
        plan.loss(),
        recovery_hint.as_deref(),
    )
}

fn confirm_trust_store_reset(plan: &TrustStoreResetPlan) -> Result<bool> {
    prompt_yes_no(&build_plan_reset_prompt(plan), false)
}

/// Run the trust store reset flow, answering its prompt from a reader.
///
/// The warning, the decline path and the reset itself stay in
/// `recover_prepared_trust_store`; only the confirmation is swapped, because
/// the production prompt needs a terminal.
#[cfg(test)]
pub(crate) fn recover_invalid_trust_store_with_reader<R>(
    command: &TrustListCommand,
    token: TrustStoreRecoveryToken,
    error: Error,
    reader: R,
    is_interactive: bool,
) -> Result<()>
where
    R: BufRead,
{
    let plan =
        build_trust_store_reset_plan_from_list_command(command, token, error, is_interactive)?;
    recover_prepared_trust_store(&plan, |plan| {
        prompt_yes_no_with_reader(&build_plan_reset_prompt(plan), false, reader)
    })
}

/// Ask for the deletion, saying first what it costs and how to avoid it.
///
/// The recovery route was printed with the warning, several lines above the
/// question. Restating it here puts it in front of the operator at the moment
/// they answer, which is when it decides what they answer.
fn trust_store_reset_prompt(
    path: &std::path::Path,
    cause: TrustStoreResetCause,
    loss: Option<TrustStoreResetLoss>,
    recovery_hint: Option<&str>,
) -> String {
    [
        describe_reset_loss(loss),
        recovery_hint.map(str::to_string),
        Some(trust_store_reset_question(path, cause)),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ")
}

fn trust_store_reset_question(path: &std::path::Path, cause: TrustStoreResetCause) -> String {
    match cause {
        TrustStoreResetCause::InvalidDocument => format!(
            "Delete invalid local trust store '{}' and continue with an empty trust cache?",
            format_path_relative_to_cwd(path)
        ),
        TrustStoreResetCause::MissingSignerKey => format!(
            "Delete local trust store '{}' because its signer key is unavailable and continue with an empty trust cache?",
            format_path_relative_to_cwd(path)
        ),
    }
}

/// State how many approvals the deletion discards.
///
/// Content that would not load names no number, so the operator is asked the
/// plain question rather than told a figure nothing stands behind.
fn describe_reset_loss(loss: Option<TrustStoreResetLoss>) -> Option<String> {
    let loss = loss?;
    Some(format!(
        "This discards {} and {}.",
        count_label(loss.known_keys, "approved key", "approved keys"),
        count_label(
            loss.recipient_sets,
            "approved recipient set",
            "approved recipient sets"
        ),
    ))
}

fn count_label(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("{count} {singular}")
    } else {
        format!("{count} {plural}")
    }
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/cli_common_trust_reset_retry_test.rs"]
mod tests;
