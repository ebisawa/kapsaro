// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! rewrap command - recipient management for encrypted files

use crate::cli::common::command::{
    resolve_options_with_read_trust_allowances, resolve_trust_store_owner_member,
};
use crate::cli::common::trust::run_with_trust_store_reset_recovery;
use crate::cli::options::{
    AllowExpiredKeyOption, AllowNonMemberOption, MemberHandleOption, SigningQuietOutputOptions,
};
use clap::Args;
use secretenv_core::Result;
use std::path::PathBuf;

mod batch;
mod promotion;

#[derive(Args, Clone)]
pub(crate) struct RewrapArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningQuietOutputOptions,

    #[command(flatten)]
    pub allow_expired_key: AllowExpiredKeyOption,

    #[command(flatten)]
    pub allow_non_member: AllowNonMemberOption,

    /// Clear removed_recipients history
    #[arg(long)]
    pub clear_disclosure_history: bool,

    #[command(flatten)]
    pub member: MemberHandleOption,

    /// Rotate content key (full re-encryption)
    #[arg(long)]
    pub rotate_key: bool,

    /// Explicit encrypted artifact path to rewrap; when specified, only these files are processed
    #[arg(long = "target", value_name = "path")]
    pub targets: Vec<PathBuf>,
}

pub(crate) fn run(args: RewrapArgs) -> Result<()> {
    let options = resolve_options_with_read_trust_allowances(
        &args.common,
        args.allow_expired_key.allow_expired_key,
        args.allow_non_member.allow_non_member,
    )?;
    run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, args.member.member_handle.clone()),
        || batch::run_batch_rewrap(&args, &options),
    )
}
