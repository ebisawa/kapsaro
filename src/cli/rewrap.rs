// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! rewrap command - recipient management for encrypted files

use crate::cli::common::command::{resolve_options, resolve_trust_store_owner_member};
use crate::cli::common::trust::run_with_trust_store_reset_recovery;
use crate::cli::options::CommonOptions;
use crate::Result;
use clap::Args;

mod batch;
mod promotion;

#[derive(Args, Clone)]
pub struct RewrapArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Clear removed_recipients history
    #[arg(long)]
    pub clear_disclosure_history: bool,

    /// Member ID to use
    #[arg(long, short = 'm')]
    pub member_id: Option<String>,

    /// Rotate content key (full re-encryption)
    #[arg(long)]
    pub rotate_key: bool,
}

pub fn run(args: RewrapArgs) -> Result<()> {
    let options = resolve_options(&args.common);
    run_with_trust_store_reset_recovery(
        &options,
        || resolve_trust_store_owner_member(&options, args.member_id.clone()),
        || batch::execute_batch_rewrap(&args),
    )
}
