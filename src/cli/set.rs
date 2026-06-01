// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! set command - set or update a key-value pair in default kv-enc file

use std::io::{self, Read};

use clap::Args;
use zeroize::Zeroizing;

use crate::cli::common::command::{
    resolve_options_with_allow_expired_key, run_kv_write_command_with_recovery, WriteCommandLabels,
};
use crate::cli::common::output::text::{print_optional_status, print_warnings};
use crate::cli::common::trust::confirm_recipient_set_approval;
use crate::cli::options::{
    AllowExpiredKeyOption, KvStoreNameOption, MemberHandleOption, SigningQuietOptions,
};
use kapsaro_core::api::kv::KvInputEntry;
use kapsaro_core::api::secret::SecretString;
use kapsaro_core::cli_api::app::kv::mutation::set_kv_command_with_recipient_set_confirmation;
use kapsaro_core::cli_api::app::trust::SetPolicy;
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
    let mut value = Some(resolve_value(args.value, args.stdin)?);
    let options = resolve_options_with_allow_expired_key(
        &args.common,
        args.allow_expired_key.allow_expired_key,
    )?;
    let outcome = run_kv_write_command_with_recovery::<SetPolicy, _, _>(
        &options,
        args.member.member_handle.clone(),
        args.store.name.as_deref(),
        true,
        WriteCommandLabels {
            signer_context: Some(("set input signer", "input signer")),
            recipient_context: "set recipients",
        },
        |_, trust_plan| {
            let success_message = format!(
                "Set key '{}' in '{}'",
                args.key,
                args.store.name.as_deref().unwrap_or("default")
            );
            let value = value.take().ok_or_else(|| {
                Error::build_invalid_operation_error("Set value was already consumed")
            })?;
            set_kv_command_with_recipient_set_confirmation(
                trust_plan,
                vec![KvInputEntry::new(args.key.clone(), value)],
                Some(&success_message),
                confirm_recipient_set_approval,
            )
        },
    )?;
    print_warnings(&outcome.warnings);
    print_optional_status(outcome.message.as_deref(), args.common.quiet.quiet);
    Ok(())
}
