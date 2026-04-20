// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! unset command - remove a key from default kv-enc file

use clap::Args;
#[cfg(test)]
use std::io::BufRead;

use crate::app::kv::mutation::unset_kv_command;
use crate::app::trust::UnsetPolicy;
use crate::cli::common::command::{
    resolve_options, resolve_required_member_id, resolve_trust_store_owner_member,
    run_kv_write_command_with_trust, WriteCommandLabels,
};
use crate::cli::common::output::text::print_optional_status;
use crate::cli::common::prompt::prompt_yes_no;
#[cfg(test)]
use crate::cli::common::prompt::prompt_yes_no_with_reader;
use crate::cli::common::trust::run_with_trust_store_reset_recovery;
use crate::cli::options::CommonOptions;
use crate::support::tty;
use crate::{Error, Result};

#[derive(Args)]
pub struct UnsetArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Force removal without confirmation
    #[arg(long, short = 'f')]
    pub force: bool,

    /// Member handle to use
    #[arg(long = "member-handle", short = 'm', value_name = "MEMBER_HANDLE")]
    pub member_id: Option<String>,

    /// Secret store name; defaults to "default"
    #[arg(long, short = 'n')]
    pub name: Option<String>,

    /// Key name to remove
    pub key: String,
}

pub fn run(args: UnsetArgs) -> Result<()> {
    let options = resolve_options(&args.common);
    let member_id = resolve_required_member_id(&options, args.member_id.clone(), false)?;
    confirm_unset_operation(args.force, &args.key)?;
    let outcome = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, Some(member_id.clone())),
        || {
            run_kv_write_command_with_trust::<UnsetPolicy, _, _>(
                &args.common,
                Some(member_id.clone()),
                args.name.as_deref(),
                false,
                WriteCommandLabels {
                    signer_context: Some(("unset input signer", "input signer")),
                    recipient_context: "unset recipients",
                },
                |_, trust_plan| {
                    let success_message = format!(
                        "Removed key '{}' from '{}'",
                        args.key,
                        args.name.as_deref().unwrap_or("default")
                    );
                    unset_kv_command(trust_plan, &args.key, Some(&success_message))
                },
            )
        },
    )?;
    print_optional_status(outcome.message.as_deref(), args.common.quiet);
    Ok(())
}

fn confirm_unset_operation(force: bool, key: &str) -> Result<()> {
    if force {
        return Ok(());
    }
    if !tty::is_interactive() {
        return Err(Error::InvalidOperation {
            message: format!(
                "Refusing to unset '{}' without --force in non-interactive mode",
                key
            ),
        });
    }

    if prompt_yes_no(&format!("Remove '{}' from the secret store?", key), false)? {
        return Ok(());
    }

    Err(Error::InvalidOperation {
        message: format!("Unset operation cancelled for '{}'", key),
    })
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
        return Err(Error::InvalidOperation {
            message: format!(
                "Refusing to unset '{}' without --force in non-interactive mode",
                key
            ),
        });
    }

    if prompt_yes_no_with_reader(
        &format!("Remove '{}' from the secret store?", key),
        false,
        &mut reader,
    )? {
        return Ok(());
    }

    Err(Error::InvalidOperation {
        message: format!("Unset operation cancelled for '{}'", key),
    })
}

#[cfg(test)]
#[path = "../../tests/unit/cli_unset_test.rs"]
mod tests;
