// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! unset command - remove a key from default kv-enc file

use clap::Args;
#[cfg(test)]
use std::io::BufRead;

use crate::cli::common::command::{
    resolve_cli_write_session, resolve_required_cli_member_handle,
    run_kv_write_command_with_recovery, CliWriteSession, WriteCommandLabels,
};
use crate::cli::common::context::CliContext;
use crate::cli::common::output::text::print_optional_status;
use crate::cli::common::prompt::confirm_destructive_action;
#[cfg(test)]
use crate::cli::common::prompt::confirm_destructive_action_with_reader;
use crate::cli::common::trust::confirm_recipient_set_approval;
use crate::cli::options::{
    AllowExpiredKeyOption, ForceOption, KvStoreNameOption, MemberHandleOption, SigningQuietOptions,
};
use kapsaro_core::api::kv::mutation::unset_kv_command_with_recipient_set_confirmation;
use kapsaro_core::api::kv::types::KvWriteOutcome;
use kapsaro_core::api::workspace::WorkspaceWriteDirectories;
use kapsaro_core::Result;

#[derive(Args)]
pub(crate) struct UnsetArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningQuietOptions,

    #[command(flatten)]
    pub allow_expired_key: AllowExpiredKeyOption,

    #[command(flatten)]
    pub force: ForceOption,

    #[command(flatten)]
    pub member: MemberHandleOption,

    #[command(flatten)]
    pub store: KvStoreNameOption,

    /// Key name to remove
    pub key: String,
}

pub(crate) fn run(args: UnsetArgs) -> Result<()> {
    let context = CliContext::resolve(&args.common)?;
    let allow_expired_key = context.allow_expired_key(args.allow_expired_key.allow_expired_key)?;
    let workspace_path = context.workspace_path()?;
    let directories = WorkspaceWriteDirectories::open(workspace_path)?;
    let member_handle =
        resolve_required_cli_member_handle(&context, args.member.member_handle.clone(), false)?;
    confirm_unset_operation(args.force.force, &args.key)?;
    let session = resolve_cli_write_session(
        &context,
        &args.common,
        directories,
        Some(member_handle),
        allow_expired_key,
    )?;
    let outcome = remove_entry(&session, args.store.name.as_deref(), &args.key)?;
    print_optional_status(outcome.message.as_deref(), args.common.quiet.quiet);
    Ok(())
}

fn remove_entry(
    session: &CliWriteSession,
    store_name: Option<&str>,
    key: &str,
) -> Result<KvWriteOutcome> {
    let success_message = format!(
        "Removed key '{}' from '{}'",
        key,
        store_name.unwrap_or("default")
    );
    run_kv_write_command_with_recovery(
        session,
        store_name,
        false,
        WriteCommandLabels {
            signer_context: Some(("unset input signer", "input signer")),
            recipient_context: "unset recipients",
        },
        |trust_plan| {
            unset_kv_command_with_recipient_set_confirmation(
                trust_plan,
                key,
                Some(&success_message),
                confirm_recipient_set_approval,
            )
        },
    )
}

fn confirm_unset_operation(force: bool, key: &str) -> Result<()> {
    confirm_destructive_action(
        force,
        &unset_prompt(key),
        unset_non_interactive_error(key),
        unset_cancelled_error(key),
    )?;
    Ok(())
}

/// Confirm an unset against a reader rather than the terminal.
///
/// Wording and error mapping are shared with `confirm_unset_operation`; only
/// the prompt is swapped, because the production one needs a terminal.
#[cfg(test)]
fn confirm_unset_operation_with_reader<R>(
    force: bool,
    key: &str,
    is_interactive: bool,
    mut reader: R,
) -> Result<()>
where
    R: BufRead,
{
    confirm_destructive_action_with_reader(
        force,
        &unset_prompt(key),
        unset_non_interactive_error(key),
        unset_cancelled_error(key),
        is_interactive,
        &mut reader,
    )?;
    Ok(())
}

fn unset_prompt(key: &str) -> String {
    format!("Remove '{}' from the secret store?", key)
}

fn unset_non_interactive_error(key: &str) -> String {
    format!(
        "Unset requires --force.\n\
         Key: {}\n\
         Reason: non-interactive mode.",
        key
    )
}

fn unset_cancelled_error(key: &str) -> String {
    format!("Unset operation cancelled for '{}'", key)
}

#[cfg(test)]
#[path = "../../tests/unit/internal/cli_unset_test.rs"]
mod tests;
