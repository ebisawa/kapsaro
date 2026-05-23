// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! get command - get and decrypt key-value entries from default kv-enc file

use clap::Args;

use crate::cli::common::command::{
    resolve_options_with_allow_expired_key, run_read_command_with_recovery, ReadCommandLabels,
};
use crate::cli::common::output::kv::print_kv_read_result;
use crate::cli::options::{
    AllowExpiredKeyOption, KvStoreNameOption, MemberHandleOption, SigningOutputOptions,
};
use secretenv_core::cli_api::app::kv::query::{execute_kv_read_command, resolve_kv_read_command};
use secretenv_core::cli_api::app::kv::types::KvReadMode;
use secretenv_core::cli_api::app::trust::GetPolicy;
use secretenv_core::{Error, Result};

#[derive(Args)]
pub(crate) struct GetArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningOutputOptions,

    #[command(flatten)]
    pub allow_expired_key: AllowExpiredKeyOption,

    /// Output all entries
    #[arg(long, short = 'a')]
    pub all: bool,

    #[command(flatten)]
    pub member: MemberHandleOption,

    #[command(flatten)]
    pub store: KvStoreNameOption,

    /// Output in KEY="VALUE" format
    #[arg(long, short = 'k')]
    pub with_key: bool,

    /// Key name to retrieve
    pub key: Option<String>,
}

pub(crate) fn run(args: GetArgs) -> Result<()> {
    let read_mode = resolve_get_read_mode(args.all, args.key.as_deref())?;
    let options = resolve_options_with_allow_expired_key(
        &args.common,
        args.allow_expired_key.allow_expired_key,
    )?;
    let kv_map = run_read_command_with_recovery(
        &options,
        args.member.member_handle.clone(),
        ReadCommandLabels {
            context: "get signer",
            subject: "signer",
            allow_non_member: true,
        },
        |ssh_ctx| {
            resolve_kv_read_command::<GetPolicy>(
                &options,
                args.member.member_handle.clone(),
                args.store.name.as_deref(),
                ssh_ctx,
            )
        },
        |command| execute_kv_read_command(command, read_mode, args.common.debug.debug),
    )?;

    print_kv_read_result(
        &kv_map,
        if args.all { None } else { args.key.as_deref() },
        args.common.json.json,
        args.with_key,
    )
}

fn resolve_get_read_mode(all: bool, key: Option<&str>) -> Result<KvReadMode<'_>> {
    match (all, key) {
        (true, Some(_)) => Err(Error::build_invalid_operation_error(
            "--all and KEY argument cannot be used together",
        )),
        (true, None) => Ok(KvReadMode::All),
        (false, Some(key)) => Ok(KvReadMode::Single(key)),
        (false, None) => Err(Error::build_invalid_operation_error(
            "KEY argument is required (or use --all to get all entries)",
        )),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/internal/cli_get_test.rs"]
mod tests;
