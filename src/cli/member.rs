// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! member command v3 implementation
//!
//! Provides member management commands:
//! - list: Show all members in workspace
//! - show: Show specific member details
//! - remove: Remove member from workspace
//! - verify: Verify member's GitHub identity online

use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::cli::options::CommonOptions;
use crate::Error;

mod add;
mod list;
mod remove;
mod show;
mod verify;

#[derive(Args)]
#[command(disable_help_subcommand = true)]
pub struct MemberArgs {
    #[command(subcommand)]
    pub command: MemberCommands,
}

#[derive(Subcommand)]
pub enum MemberCommands {
    /// Add member's public key to incoming
    Add(AddArgs),

    /// List all members in workspace
    List(ListArgs),

    /// Remove member from workspace
    Remove(RemoveArgs),

    /// Show member details
    Show(ShowArgs),

    /// Verify member's GitHub identity online
    Verify(VerifyArgs),
}

#[derive(Args)]
pub struct AddArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Path to PublicKey JSON file
    pub filename: PathBuf,

    /// Force overwrite if member already exists in incoming
    #[arg(long, short = 'f')]
    pub force: bool,
}

#[derive(Args)]
pub struct ListArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,
}

#[derive(Args)]
pub struct ShowArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Member ID to show
    pub member_id: String,
}

#[derive(Args)]
pub struct RemoveArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Member ID to remove
    pub member_id: String,

    /// Force removal without confirmation
    #[arg(long, short = 'f')]
    pub force: bool,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Member ID to use for trust store owner resolution
    #[arg(long, short = 'm')]
    pub member_id: Option<String>,

    /// Approve verified members and add to local trust store
    #[arg(long)]
    pub approve: bool,

    /// Member IDs to verify (verifies all members if not specified)
    pub member_ids: Vec<String>,
}

pub fn run(args: MemberArgs) -> Result<(), Error> {
    match args.command {
        MemberCommands::Add(args) => add::run(args),
        MemberCommands::List(args) => list::run(args),
        MemberCommands::Remove(args) => remove::run(args),
        MemberCommands::Show(args) => show::run(args),
        MemberCommands::Verify(args) => verify::run(args),
    }
}
