// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! join command implementation
//!
//! Joins an existing workspace without creating directory structure:
//! 1. Determines member_id (CLI arg → config → keystore → TTY prompt)
//! 2. Ensures key exists (generates if missing)
//! 3. Verifies workspace exists (errors if not found)
//! 4. Registers member (with TTY confirmation for overwrites)

use clap::Args;

use crate::app::registration::types::RegistrationMode;
use crate::cli::options::CommonOptions;
use crate::cli::registration::execute_registration_command;
use crate::Error;

#[derive(Args)]
pub struct JoinArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Force overwrite existing member file
    #[arg(long, short = 'f')]
    pub force: bool,

    /// GitHub user (login name, used only when generating a new key)
    #[arg(long)]
    pub github_user: Option<String>,

    /// Member ID to use
    #[arg(long, short = 'm')]
    pub member_id: Option<String>,
}

/// Join an existing workspace
pub fn run(args: JoinArgs) -> Result<(), Error> {
    execute_registration_command(
        args.common,
        args.force,
        args.github_user,
        args.member_id,
        RegistrationMode::Join,
    )
}
