// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! set command - set or update a key-value pair in default kv-enc file

use std::io::{self, Read};

use clap::Args;
use zeroize::Zeroizing;

use crate::app::kv::mutation::set_kv_command_with_recipient_set_confirmation;
use crate::app::kv::types::KvInputEntry;
use crate::app::trust::SetPolicy;
use crate::cli::common::command::{
    resolve_options, resolve_trust_store_owner_member, run_kv_write_command_with_trust,
    WriteCommandLabels,
};
use crate::cli::common::output::text::{print_optional_status, print_warnings};
use crate::cli::common::trust::{
    confirm_recipient_set_approval, run_with_trust_store_reset_recovery,
};
use crate::cli::options::CommonOptions;
use crate::support::secret::SecretString;
use crate::{Error, Result};

#[derive(Args)]
pub struct SetArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Member handle to use
    #[arg(long = "member-handle", short = 'm', value_name = "MEMBER_HANDLE")]
    pub member_handle: Option<String>,

    /// Secret store name; defaults to "default"
    #[arg(long, short = 'n')]
    pub name: Option<String>,

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

pub fn run(args: SetArgs) -> Result<()> {
    let value = resolve_value(args.value, args.stdin)?;
    let options = resolve_options(&args.common);
    let outcome = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, args.member_handle.clone()),
        || {
            run_kv_write_command_with_trust::<SetPolicy, _, _>(
                &args.common,
                args.member_handle.clone(),
                args.name.as_deref(),
                true,
                WriteCommandLabels {
                    signer_context: Some(("set input signer", "input signer")),
                    recipient_context: "set recipients",
                },
                |_, trust_plan| {
                    let success_message = format!(
                        "Set key '{}' in '{}'",
                        args.key,
                        args.name.as_deref().unwrap_or("default")
                    );
                    set_kv_command_with_recipient_set_confirmation(
                        trust_plan,
                        vec![KvInputEntry::new_secret(
                            args.key.clone(),
                            SecretString::new(value.as_str().to_owned()),
                        )],
                        Some(&success_message),
                        confirm_recipient_set_approval,
                    )
                },
            )
        },
    )?;
    print_warnings(&outcome.warnings);
    print_optional_status(outcome.message.as_deref(), args.common.quiet);
    Ok(())
}
