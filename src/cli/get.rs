// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! get command - get and decrypt key-value entries from default kv-enc file

use clap::Args;

use crate::cli::common::command::{
    resolve_command_input, resolve_options_with_allow_expired_key,
    resolve_trust_store_owner_member, run_read_command_with_trust, ReadCommandLabels,
};
use crate::cli::common::output::kv::print_kv_read_result;
use crate::cli::common::trust::run_with_trust_store_reset_recovery;
use crate::cli::options::{
    AllowExpiredKeyOption, KvStoreNameOption, MemberHandleOption, SigningOutputOptions,
};
use secretenv_core::cli_api::app::kv::query::{execute_kv_read_command, resolve_kv_read_command};
use secretenv_core::cli_api::app::trust::GetPolicy;
use secretenv_core::Result;

#[derive(Args)]
pub struct GetArgs {
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

pub fn run(args: GetArgs) -> Result<()> {
    if args.all && args.key.is_some() {
        return Err(secretenv_core::Error::build_invalid_operation_error(
            "--all and KEY argument cannot be used together".to_string(),
        ));
    }
    if !args.all && args.key.is_none() {
        return Err(secretenv_core::Error::build_invalid_operation_error(
            "KEY argument is required (or use --all to get all entries)".to_string(),
        ));
    }

    let read_mode = if args.all {
        secretenv_core::cli_api::app::kv::types::KvReadMode::All
    } else {
        secretenv_core::cli_api::app::kv::types::KvReadMode::Single(
            args.key.as_deref().ok_or_else(|| {
                secretenv_core::Error::build_invalid_operation_error("KEY argument is required")
            })?,
        )
    };
    let options = resolve_options_with_allow_expired_key(
        &args.common,
        args.allow_expired_key.allow_expired_key,
    )?;
    let kv_map = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, args.member.member_handle.clone()),
        || {
            let (_, ssh_ctx) =
                resolve_command_input(&args.common, args.member.member_handle.clone())?;
            let command = resolve_kv_read_command::<GetPolicy>(
                &options,
                args.member.member_handle.clone(),
                args.store.name.as_deref(),
                ssh_ctx,
            )?;
            run_read_command_with_trust(
                &options,
                &command,
                ReadCommandLabels {
                    context: "get signer",
                    subject: "signer",
                    allow_non_member: true,
                },
                || execute_kv_read_command(&command, read_mode, args.common.debug.debug),
            )
        },
    )?;

    print_kv_read_result(
        &kv_map,
        if args.all { None } else { args.key.as_deref() },
        args.common.json.json,
        args.with_key,
    )
}
