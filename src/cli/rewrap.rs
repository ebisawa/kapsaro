// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! rewrap command - recipient management for encrypted files

use crate::cli::common::options::CommonOptions;
use crate::Result;
use clap::Args;

mod batch;
mod promotion;
#[cfg(test)]
pub(crate) use promotion::confirm_incoming_promotions;

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
    batch::execute_batch_rewrap(&args)
}

#[cfg(test)]
#[path = "../../tests/unit/cli_rewrap_internal_test.rs"]
mod tests;
