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
    resolve_options_with_allow_expired_key, run_read_command_with_recovery, ReadCommandLabels,
};
use crate::cli::options::{
    AllowExpiredKeyOption, KvStoreNameOption, MemberHandleOption, SigningOptions,
};
use kapsaro_core::cli_api::app::kv::query::resolve_kv_read_command;
use kapsaro_core::cli_api::app::run::execute_run_command;
use kapsaro_core::cli_api::app::trust::RunPolicy;
use kapsaro_core::Result;

#[derive(Args)]
pub(crate) struct RunArgs {
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

pub(crate) fn run(args: RunArgs) -> Result<i32> {
    let options = resolve_options_with_allow_expired_key(
        &args.common,
        args.allow_expired_key.allow_expired_key,
    )?;
    let exit_code = run_read_command_with_recovery(
        &options,
        args.member.member_handle.clone(),
        ReadCommandLabels {
            context: "run signer",
            subject: "run",
            allow_non_member: false,
        },
        |ssh_ctx| {
            resolve_kv_read_command::<RunPolicy>(
                &options,
                args.member.member_handle.clone(),
                args.store.name.as_deref(),
                ssh_ctx,
            )
        },
        |command| execute_run_command(command, &args.command, options.debug),
    )?;
    Ok(exit_code)
}
