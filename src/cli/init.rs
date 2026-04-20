// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! init command implementation
//!
//! Bootstraps a new workspace:
//! 1. If the workspace already has active members, exit without changes
//! 2. Determines member handle (CLI arg → config → keystore → TTY prompt)
//! 3. Ensures key exists (generates if missing)
//! 4. Creates workspace structure (members/, secrets/)
//! 5. Registers the first member directly in active/

use clap::Args;

use crate::app::registration::types::RegistrationMode;
use crate::cli::options::CommonOptions;
use crate::cli::registration::execute_registration_command;
use crate::Error;

#[derive(Args)]
pub struct InitArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// GitHub user (login name, used only when generating a new key)
    #[arg(long)]
    pub github_user: Option<String>,

    /// Member handle to use
    #[arg(long = "member-handle", short = 'm', value_name = "MEMBER_HANDLE")]
    pub member_id: Option<String>,
}

/// Initialize workspace structure and register member
pub fn run(args: InitArgs) -> Result<(), Error> {
    execute_registration_command(
        args.common,
        false,
        args.github_user,
        args.member_id,
        RegistrationMode::Init,
    )
}
