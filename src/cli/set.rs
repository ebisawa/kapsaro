// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! set command - set or update a key-value pair in default kv-enc file

use std::io::{self, Read};

use clap::Args;

use crate::app::context::options::CommonCommandOptions;
use crate::app::kv::mutation::set_kv_command;
use crate::cli::common::options::CommonOptions;
use crate::cli::common::ssh::resolve_ssh_context_optional;
use crate::{Error, Result};

#[derive(Args)]
pub struct SetArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Member ID to use
    #[arg(long, short = 'm')]
    pub member_id: Option<String>,

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
fn resolve_value(value: Option<String>, from_stdin: bool) -> Result<String> {
    if from_stdin {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        // Trim trailing newline that is typically appended by echo/pipe
        let trimmed = buf.trim_end_matches('\n').trim_end_matches('\r');
        Ok(trimmed.to_string())
    } else if let Some(v) = value {
        Ok(v)
    } else {
        Err(Error::invalid_argument(
            "VALUE is required; pass it as an argument or use --stdin",
        ))
    }
}

pub fn run(args: SetArgs) -> Result<()> {
    let value = resolve_value(args.value.clone(), args.stdin)?;
    let options = CommonCommandOptions::from(&args.common);
    let ssh_ctx = resolve_ssh_context_optional(&options, args.member_id.clone())?;
    let outcome = set_kv_command(
        options,
        args.member_id.clone(),
        args.name.as_deref(),
        vec![(args.key.clone(), value)],
        Some(&format!(
            "Set key '{}' in '{}'",
            args.key,
            args.name.as_deref().unwrap_or("default")
        )),
        ssh_ctx,
    )?;
    if let Some(message) = outcome.message {
        if !args.common.quiet {
            eprintln!("{}", message);
        }
    }
    Ok(())
}
