// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! unset command - remove a key from default kv-enc file

use clap::Args;
#[cfg(test)]
use std::io::BufRead;

use crate::cli::common::command::{
    resolve_options_with_allow_expired_key, resolve_required_member_handle,
    resolve_trust_store_owner_member, run_kv_write_command_with_trust, WriteCommandLabels,
};
use crate::cli::common::output::text::{print_optional_status, print_warnings};
use crate::cli::common::prompt::prompt_yes_no;
#[cfg(test)]
use crate::cli::common::prompt::prompt_yes_no_with_reader;
use crate::cli::common::trust::{
    confirm_recipient_set_approval, run_with_trust_store_reset_recovery,
};
use crate::cli::options::{
    AllowExpiredKeyOption, ForceOption, KvStoreNameOption, MemberHandleOption, SigningQuietOptions,
};
use secretenv_core::cli_api::app::kv::mutation::unset_kv_command_with_recipient_set_confirmation;
use secretenv_core::cli_api::app::trust::UnsetPolicy;
use secretenv_core::cli_api::presentation::tty;
use secretenv_core::{Error, Result};

#[derive(Args)]
pub struct UnsetArgs {
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

pub fn run(args: UnsetArgs) -> Result<()> {
    let options = resolve_options_with_allow_expired_key(
        &args.common,
        args.allow_expired_key.allow_expired_key,
    )?;
    let member_handle =
        resolve_required_member_handle(&options, args.member.member_handle.clone(), false)?;
    confirm_unset_operation(args.force.force, &args.key)?;
    let outcome = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, Some(member_handle.clone())),
        || {
            run_kv_write_command_with_trust::<UnsetPolicy, _, _>(
                &args.common,
                Some(member_handle.clone()),
                args.store.name.as_deref(),
                false,
                args.allow_expired_key.allow_expired_key,
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
            )
        },
    )?;
    print_warnings(&outcome.warnings);
    print_optional_status(outcome.message.as_deref(), args.common.quiet.quiet);
    Ok(())
}

fn confirm_unset_operation(force: bool, key: &str) -> Result<()> {
    if force {
        return Ok(());
    }
    if !tty::is_interactive() {
        return Err(Error::build_invalid_operation_error(format!(
            "Refusing to unset '{}' without --force in non-interactive mode",
            key
        )));
    }

    if prompt_yes_no(&format!("Remove '{}' from the secret store?", key), false)? {
        return Ok(());
    }

    Err(Error::build_invalid_operation_error(format!(
        "Unset operation cancelled for '{}'",
        key
    )))
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
    if force {
        return Ok(());
    }
    if !is_interactive {
        return Err(Error::build_invalid_operation_error(format!(
            "Refusing to unset '{}' without --force in non-interactive mode",
            key
        )));
    }

    if prompt_yes_no_with_reader(
        &format!("Remove '{}' from the secret store?", key),
        false,
        &mut reader,
    )? {
        return Ok(());
    }

    Err(Error::build_invalid_operation_error(format!(
        "Unset operation cancelled for '{}'",
        key
    )))
}

#[cfg(test)]
#[path = "../../tests/unit/internal/cli_unset_test.rs"]
mod tests;
