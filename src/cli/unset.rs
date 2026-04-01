// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! unset command - remove a key from default kv-enc file

use clap::Args;

use crate::app::context::options::CommonCommandOptions;
use crate::app::kv::mutation::unset_kv_command;
use crate::cli::common::options::CommonOptions;
use crate::cli::common::ssh::resolve_ssh_context_optional;
use crate::Result;

#[derive(Args)]
pub struct UnsetArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Force removal without confirmation
    #[arg(long, short = 'f')]
    pub force: bool,

    /// Member ID to use
    #[arg(long, short = 'm')]
    pub member_id: Option<String>,

    /// Secret store name; defaults to "default"
    #[arg(long, short = 'n')]
    pub name: Option<String>,

    /// Key name to remove
    pub key: String,
}

pub fn run(args: UnsetArgs) -> Result<()> {
    let options = CommonCommandOptions::from(&args.common);
    let ssh_ctx = resolve_ssh_context_optional(&options, args.member_id.clone())?;
    let outcome = unset_kv_command(
        options,
        args.member_id.clone(),
        args.name.as_deref(),
        &args.key,
        Some(&format!(
            "Removed key '{}' from '{}'",
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
