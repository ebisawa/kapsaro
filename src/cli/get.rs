// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! get command - get and decrypt key-value entries from default kv-enc file

use clap::Args;

use crate::app::kv::query::{build_kv_read_command, execute_kv_read_command};
use crate::app::trust::GetPolicy;
use crate::cli::common::command::{
    resolve_command_input, resolve_options, resolve_trust_store_owner_member,
    run_read_command_with_trust, ReadCommandLabels,
};
use crate::cli::common::output::kv::print_kv_read_result;
use crate::cli::common::trust::run_with_trust_store_reset_recovery;
use crate::cli::options::CommonOptions;
use crate::Result;

#[derive(Args)]
pub struct GetArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Output all entries
    #[arg(long, short = 'a')]
    pub all: bool,

    /// Member ID to use
    #[arg(long, short = 'm')]
    pub member_id: Option<String>,

    /// Secret store name; defaults to "default"
    #[arg(long, short = 'n')]
    pub name: Option<String>,

    /// Output in KEY="VALUE" format
    #[arg(long, short = 'k')]
    pub with_key: bool,

    /// Key name to retrieve
    pub key: Option<String>,
}

pub fn run(args: GetArgs) -> Result<()> {
    if args.all && args.key.is_some() {
        return Err(crate::Error::InvalidOperation {
            message: "--all and KEY argument cannot be used together".to_string(),
        });
    }
    if !args.all && args.key.is_none() {
        return Err(crate::Error::InvalidOperation {
            message: "KEY argument is required (or use --all to get all entries)".to_string(),
        });
    }

    let read_mode = if args.all {
        crate::app::kv::types::KvReadMode::All
    } else {
        crate::app::kv::types::KvReadMode::Single(
            args.key
                .as_deref()
                .ok_or_else(|| crate::Error::invalid_operation("KEY argument is required"))?,
        )
    };
    let options = resolve_options(&args.common);
    let kv_map = run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, args.member_id.clone()),
        || {
            let (_, ssh_ctx) = resolve_command_input(&args.common, args.member_id.clone())?;
            let command = build_kv_read_command::<GetPolicy>(
                &options,
                args.member_id.clone(),
                args.name.as_deref(),
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
                || execute_kv_read_command(&command, read_mode, args.common.verbose),
            )
        },
    )?;

    print_kv_read_result(
        &kv_map,
        if args.all { None } else { args.key.as_deref() },
        args.common.json,
        args.with_key,
    )
}
