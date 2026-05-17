// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! rewrap command - recipient management for encrypted files

use crate::cli::common::command::{resolve_options, resolve_trust_store_owner_member};
use crate::cli::common::trust::run_with_trust_store_reset_recovery;
use crate::cli::options::{MemberHandleOption, SigningQuietOutputOptions};
use clap::Args;
use secretenv_core::Result;
use std::path::PathBuf;

mod batch;
mod promotion;

#[derive(Args, Clone)]
pub struct RewrapArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningQuietOutputOptions,

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

pub fn run(args: RewrapArgs) -> Result<()> {
    let options = resolve_options(&args.common);
    run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, args.member.member_handle.clone()),
        || batch::run_batch_rewrap(&args),
    )
}
