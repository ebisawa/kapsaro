// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! run command v3 implementation
//!
//! Executes a command with decrypted environment variables.
//!
//! Features:
//! - Uses default kv-enc file (<workspace>/secrets/default.kvenc)
//! - Automatic verify --strict before decryption (MUST - cannot be skipped)
//! - Child process execution with decrypted environment
//! - Exit code forwarding

use clap::Args;

use crate::app::kv::query::resolve_kv_read_command;
use crate::app::run::execute_run_command;
use crate::app::trust::RunPolicy;
use crate::cli::common::command::{
    resolve_command_input, resolve_options, resolve_trust_store_owner_member,
    run_read_command_with_trust, ReadCommandLabels,
};
use crate::cli::common::trust::run_with_trust_store_reset_recovery;
use crate::cli::options::CommonOptions;
use crate::Result;

#[derive(Args)]
pub struct RunArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Member handle to use
    #[arg(long = "member-handle", short = 'm', value_name = "MEMBER_HANDLE")]
    pub member_handle: Option<String>,

    /// Secret store name; defaults to "default"
    #[arg(long, short = 'n')]
    pub name: Option<String>,

    /// Command to execute (after --)
    #[arg(required = true, last = true)]
    pub command: Vec<String>,
}

pub fn run(args: RunArgs) -> Result<()> {
    let options = resolve_options(&args.common);
    let exit_code = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, args.member_handle.clone()),
        || {
            let (_, ssh_ctx) = resolve_command_input(&args.common, args.member_handle.clone())?;
            let command = resolve_kv_read_command::<RunPolicy>(
                &options,
                args.member_handle.clone(),
                args.name.as_deref(),
                ssh_ctx,
            )?;
            run_read_command_with_trust(
                &options,
                &command,
                ReadCommandLabels {
                    context: "run signer",
                    subject: "run",
                    allow_non_member: false,
                },
                || execute_run_command(&command, &args.command),
            )
        },
    )?;
    std::process::exit(exit_code);
}
