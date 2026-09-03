// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! set command - set or update a key-value pair in default kv-enc file

use std::io::{self, Read};

use clap::Args;
use zeroize::Zeroizing;

use crate::cli::common::command::{
    resolve_cli_write_session, run_kv_write_command_with_recovery, CliWriteSession,
    WriteCommandLabels,
};
use crate::cli::common::context::CliContext;
use crate::cli::common::output::text::print_optional_status;
use crate::cli::common::trust::confirm_recipient_set_approval;
use crate::cli::options::{
    AllowExpiredKeyOption, KvStoreNameOption, MemberHandleOption, SigningQuietOptions,
};
use kapsaro_core::api::kv::mutation::set_kv_command_with_recipient_set_confirmation;
use kapsaro_core::api::kv::types::KvWriteOutcome;
use kapsaro_core::api::kv::KvInputEntry;
use kapsaro_core::api::secret::SecretString;
use kapsaro_core::api::workspace::WorkspaceWriteDirectories;
use kapsaro_core::{Error, Result};

#[derive(Args)]
pub(crate) struct SetArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningQuietOptions,

    #[command(flatten)]
    pub allow_expired_key: AllowExpiredKeyOption,

    #[command(flatten)]
    pub member: MemberHandleOption,

    #[command(flatten)]
    pub store: KvStoreNameOption,

    /// Read VALUE from stdin (avoids shell history exposure)
    #[arg(long, conflicts_with = "value")]
    pub stdin: bool,

    /// Key name
    pub key: String,

    /// Value to set (omit when using --stdin)
    pub value: Option<String>,
}

/// Resolve the value from either the positional argument or stdin.
fn resolve_value(value: Option<String>, from_stdin: bool) -> Result<SecretString> {
    if from_stdin {
        let mut buf = Zeroizing::new(String::new());
        io::stdin().read_to_string(&mut buf)?;
        // Trim trailing newline that is typically appended by echo/pipe
        while matches!(buf.chars().last(), Some('\n' | '\r')) {
            buf.pop();
        }
        Ok(SecretString::from_zeroizing(buf))
    } else if let Some(v) = value {
        Ok(SecretString::new(v))
    } else {
        Err(Error::build_invalid_argument_error(
            "VALUE is required; pass it as an argument or use --stdin",
        ))
    }
}

pub(crate) fn run(args: SetArgs) -> Result<()> {
    let value = resolve_value(args.value, args.stdin)?;
    let context = CliContext::resolve(&args.common)?;
    let allow_expired_key = context.allow_expired_key(args.allow_expired_key.allow_expired_key)?;
    let workspace_path = context.workspace_path()?;
    let directories = WorkspaceWriteDirectories::open(workspace_path)?;
    let session = resolve_cli_write_session(
        &context,
        &args.common,
        directories,
        args.member.member_handle.clone(),
        allow_expired_key,
    )?;
    let outcome = set_entry(&session, args.store.name.as_deref(), &args.key, value)?;
    print_optional_status(outcome.message.as_deref(), args.common.quiet.quiet);
    Ok(())
}

fn set_entry(
    session: &CliWriteSession,
    store_name: Option<&str>,
    key: &str,
    value: SecretString,
) -> Result<KvWriteOutcome> {
    let success_message = format!("Set key '{}' in '{}'", key, store_name.unwrap_or("default"));
    run_kv_write_command_with_recovery(
        session,
        store_name,
        true,
        WriteCommandLabels {
            signer_context: Some(("set input signer", "input signer")),
            recipient_context: "set recipients",
        },
        |trust_plan| {
            let entry = KvInputEntry::new(key.to_string(), copy_set_value(&value));
            set_kv_command_with_recipient_set_confirmation(
                trust_plan,
                vec![entry],
                Some(&success_message),
                confirm_recipient_set_approval,
            )
        },
    )
}

/// Copy the value one write attempt sends.
///
/// A trust store reset runs the write once more, so each attempt takes its own
/// copy of the value the command still holds. Moving the value into the first
/// attempt would leave the retry with nothing to write.
fn copy_set_value(value: &SecretString) -> SecretString {
    SecretString::new(value.expose_secret().to_string())
}

#[cfg(test)]
#[path = "../../tests/unit/internal/cli_set_test.rs"]
mod tests;
