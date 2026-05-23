// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! join command implementation
//!
//! Joins an existing workspace without creating directory structure:
//! 1. Determines member handle (CLI arg → config → keystore → TTY prompt)
//! 2. Ensures key exists (generates if missing)
//! 3. Verifies workspace exists (errors if not found)
//! 4. Registers member (with TTY confirmation for overwrites)

use clap::Args;

use crate::cli::options::{ForceOption, MemberHandleOption, SigningOptions};
use crate::cli::registration::run_registration_command;
use secretenv_core::cli_api::app::registration::types::RegistrationMode;
use secretenv_core::Error;

#[derive(Args)]
pub(crate) struct JoinArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningOptions,

    #[command(flatten)]
    pub force: ForceOption,

    /// GitHub user (login name, used only when generating a new key)
    #[arg(long)]
    pub github_user: Option<String>,

    #[command(flatten)]
    pub member: MemberHandleOption,
}

/// Join an existing workspace
pub(crate) fn run(args: JoinArgs) -> Result<(), Error> {
    run_registration_command(
        args.common,
        args.force.force,
        args.github_user,
        args.member.member_handle,
        RegistrationMode::Join,
    )
}
