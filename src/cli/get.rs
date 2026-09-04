// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! get command - get and decrypt key-value entries from default kv-enc file

use clap::Args;

use crate::cli::common::command::ReadCommandLabels;
use crate::cli::common::kv_read::{KvReadSession, NonMemberReviewMode};
use crate::cli::common::output::kv::{print_kv_read_result, KvReadResult};
use crate::cli::common::presentation::format_path_relative_to_cwd;
use crate::cli::options::{
    AllowExpiredKeyOption, AllowNonMemberOption, KvStoreNameOption, MemberHandleOption,
    SigningOutputOptions,
};
use kapsaro_core::api::kv::{is_missing_key_error, KvReadOperation};
use kapsaro_core::{Error, Result};

#[derive(Args)]
pub(crate) struct GetArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningOutputOptions,

    #[command(flatten)]
    pub allow_expired_key: AllowExpiredKeyOption,

    #[command(flatten)]
    pub allow_non_member: AllowNonMemberOption,

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
    let session = open_get_session(&args)?;
    let operation = match read_mode {
        KvReadMode::All => KvReadOperation::Entries,
        KvReadMode::Single(key) => KvReadOperation::Entry(key.to_string()),
    };
    let result = session
        .authorize(
            operation,
            ReadCommandLabels {
                context: "get signer",
                allow_non_member: session.allow_non_member(),
            },
        )?
        .into_value()
        .get_result()
        .map_err(|error| match read_mode {
            KvReadMode::Single(key) => {
                annotate_missing_key_error(error, session.artifact_path(), key)
            }
            KvReadMode::All => error,
        })?;
    let (values, disclosed) = result.into_parts();
    let kv_map = KvReadResult { values, disclosed };

    print_kv_read_result(
        &kv_map,
        if args.all { None } else { args.key.as_deref() },
        args.common.json.json,
        args.with_key,
    )
}

fn annotate_missing_key_error(error: Error, input_path: &std::path::Path, key: &str) -> Error {
    if !is_missing_key_error(&error, key) {
        return error;
    }
    Error::build_not_found_error(format!(
        "{} in {}",
        error.format_user_message(),
        format_path_relative_to_cwd(input_path)
    ))
}

fn open_get_session(args: &GetArgs) -> Result<KvReadSession> {
    KvReadSession::open(
        &args.common,
        args.allow_expired_key.allow_expired_key,
        NonMemberReviewMode::Configured(args.allow_non_member.allow_non_member),
        args.store.name.as_deref(),
        args.member.member_handle.clone(),
    )
}

#[derive(Clone, Copy)]
enum KvReadMode<'a> {
    All,
    Single(&'a str),
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
mod cli_get_test;
