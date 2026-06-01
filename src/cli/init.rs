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

use crate::cli::options::{MemberHandleOption, SigningOptions};
use crate::cli::registration::run_registration_command;
use kapsaro_core::cli_api::app::registration::types::RegistrationMode;
use kapsaro_core::Error;

#[derive(Args)]
pub(crate) struct InitArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningOptions,

    /// GitHub user (login name, used only when generating a new key)
    #[arg(long)]
    pub github_user: Option<String>,

    #[command(flatten)]
    pub member: MemberHandleOption,
}

/// Initialize workspace structure and register member
pub(crate) fn run(args: InitArgs) -> Result<(), Error> {
    run_registration_command(
        args.common,
        false,
        args.github_user,
        args.member.member_handle,
        RegistrationMode::Init,
    )
}
