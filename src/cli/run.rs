// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! run command v3 implementation
//!
//! Executes a command with decrypted environment variables.
//!
//! Features:
//! - Uses default kv-enc file (`<workspace>/secrets/default.kvenc`)
//! - Automatic verify --strict before decryption (MUST - cannot be skipped)
//! - Child process execution with decrypted environment
//! - Exit code forwarding

use clap::Args;

use crate::cli::common::command::{
    resolve_command_input, resolve_options_with_allow_expired_key,
    resolve_trust_store_owner_member, run_read_command_with_trust, ReadCommandLabels,
};
use crate::cli::common::trust::run_with_trust_store_reset_recovery;
use crate::cli::options::{
    AllowExpiredKeyOption, KvStoreNameOption, MemberHandleOption, SigningOptions,
};
use secretenv_core::cli_api::app::kv::query::resolve_kv_read_command;
use secretenv_core::cli_api::app::run::execute_run_command;
use secretenv_core::cli_api::app::trust::RunPolicy;
use secretenv_core::Result;

#[derive(Args)]
pub struct RunArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningOptions,

    #[command(flatten)]
    pub allow_expired_key: AllowExpiredKeyOption,

    #[command(flatten)]
    pub member: MemberHandleOption,

    #[command(flatten)]
    pub store: KvStoreNameOption,

    /// Command to execute (after --)
    #[arg(required = true, last = true)]
    pub command: Vec<String>,
}

pub fn run(args: RunArgs) -> Result<()> {
    let options = resolve_options_with_allow_expired_key(
        &args.common,
        args.allow_expired_key.allow_expired_key,
    )?;
    let exit_code = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, args.member.member_handle.clone()),
        || {
            let (_, ssh_ctx) =
                resolve_command_input(&args.common, args.member.member_handle.clone())?;
            let command = resolve_kv_read_command::<RunPolicy>(
                &options,
                args.member.member_handle.clone(),
                args.store.name.as_deref(),
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
