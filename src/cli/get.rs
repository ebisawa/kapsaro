// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! get command - get and decrypt key-value entries from default kv-enc file

use clap::Args;

use std::collections::BTreeMap;
use std::path::Path;

use crate::cli::common::command::{resolve_options_with_read_trust_allowances, ReadCommandLabels};
use crate::cli::common::kv_read::{KvReadReview, KvReadSession};
use crate::cli::common::output::kv::{print_kv_read_result, KvReadResult};
use crate::cli::options::{
    AllowExpiredKeyOption, AllowNonMemberOption, KvStoreNameOption, MemberHandleOption,
    SigningOutputOptions,
};
use kapsaro_core::api::kv::KvReadOperation;
use kapsaro_core::api::secret::SecretString;
use kapsaro_core::cli_api::app::errors::build_kv_key_not_found_error;
use kapsaro_core::cli_api::app::kv::query::evaluate_kv_read_trust_plan;
use kapsaro_core::cli_api::app::trust::GetPolicy;
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
    let kv_map = session.read(
        ReadCommandLabels {
            context: "get signer",
            subject: "signer",
            allow_non_member: session.allow_non_member(),
        },
        "KV get authorization",
        evaluate_kv_read_trust_plan::<GetPolicy>,
        |review| {
            Ok(KvReadResult {
                values: decrypt_requested_values(review, read_mode, session.artifact_path())?,
                disclosed: review.authorize(KvReadOperation::List)?.list_entry_keys()?,
            })
        },
    )?;

    print_kv_read_result(
        &kv_map,
        if args.all { None } else { args.key.as_deref() },
        args.common.json.json,
        args.with_key,
    )
}

fn open_get_session(args: &GetArgs) -> Result<KvReadSession> {
    let options = resolve_options_with_read_trust_allowances(
        &args.common,
        args.allow_expired_key.allow_expired_key,
        args.allow_non_member.allow_non_member,
    )?;
    KvReadSession::open(
        options,
        args.store.name.as_deref(),
        args.member.member_handle.clone(),
    )
}

fn decrypt_requested_values(
    review: &KvReadReview<'_>,
    read_mode: KvReadMode<'_>,
    artifact_path: &Path,
) -> Result<BTreeMap<String, SecretString>> {
    match read_mode {
        KvReadMode::All => review
            .authorize(KvReadOperation::Entries)?
            .decrypt_entries(),
        KvReadMode::Single(key) => {
            let value = review
                .authorize(KvReadOperation::Entry(key.to_string()))?
                .decrypt_entry()
                .map_err(|error| build_kv_key_not_found_error(error, artifact_path, key))?;
            Ok(BTreeMap::from([(key.to_string(), value)]))
        }
    }
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
mod tests;
