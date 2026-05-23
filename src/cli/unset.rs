// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! unset command - remove a key from default kv-enc file

use clap::Args;
#[cfg(test)]
use std::io::BufRead;

use crate::cli::common::command::{
    resolve_options_with_allow_expired_key, resolve_required_member_handle,
    run_kv_write_command_with_recovery, WriteCommandLabels,
};
use crate::cli::common::output::text::{print_optional_status, print_warnings};
use crate::cli::common::prompt::confirm_destructive_action;
#[cfg(test)]
use crate::cli::common::prompt::confirm_destructive_action_with_reader;
use crate::cli::common::trust::confirm_recipient_set_approval;
use crate::cli::options::{
    AllowExpiredKeyOption, ForceOption, KvStoreNameOption, MemberHandleOption, SigningQuietOptions,
};
use secretenv_core::cli_api::app::kv::mutation::unset_kv_command_with_recipient_set_confirmation;
use secretenv_core::cli_api::app::trust::UnsetPolicy;
use secretenv_core::Result;

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
    let options = resolve_options_with_allow_expired_key(
        &args.common,
        args.allow_expired_key.allow_expired_key,
    )?;
    let member_handle =
        resolve_required_member_handle(&options, args.member.member_handle.clone(), false)?;
    confirm_unset_operation(args.force.force, &args.key)?;
    let outcome = run_kv_write_command_with_recovery::<UnsetPolicy, _, _>(
        &options,
        Some(member_handle.clone()),
        args.store.name.as_deref(),
        false,
        WriteCommandLabels {
            signer_context: Some(("unset input signer", "input signer")),
            recipient_context: "unset recipients",
        },
        |_, trust_plan| {
            let success_message = format!(
                "Removed key '{}' from '{}'",
                args.key,
                args.store.name.as_deref().unwrap_or("default")
            );
            unset_kv_command_with_recipient_set_confirmation(
                trust_plan,
                &args.key,
                Some(&success_message),
                confirm_recipient_set_approval,
            )
        },
    )?;
    print_warnings(&outcome.warnings);
    print_optional_status(outcome.message.as_deref(), args.common.quiet.quiet);
    Ok(())
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
        "Refusing to unset '{}' without --force in non-interactive mode",
        key
    )
}

fn unset_cancelled_error(key: &str) -> String {
    format!("Unset operation cancelled for '{}'", key)
}

#[cfg(test)]
#[path = "../../tests/unit/internal/cli_unset_test.rs"]
mod tests;
