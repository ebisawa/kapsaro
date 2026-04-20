// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! trust subcommand: list, remove, purge

use clap::{Args, Subcommand};

use crate::cli::options::CommonOptions;
use crate::Error;

mod list;
mod purge;
mod remove;

#[derive(Args)]
#[command(disable_help_subcommand = true)]
pub struct TrustArgs {
    #[command(subcommand)]
    pub command: TrustCommands,
}

#[derive(Subcommand)]
pub enum TrustCommands {
    /// List known keys in local trust store
    List(ListArgs),

    /// Remove a known key from local trust store
    Remove(RemoveArgs),

    /// Purge old known keys from local trust store
    Purge(PurgeArgs),
}

#[derive(Args)]
pub struct ListArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Member handle (owner of the trust store to list)
    #[arg(long = "member-handle", short = 'm', value_name = "MEMBER_HANDLE")]
    pub member_id: Option<String>,
}

#[derive(Args)]
pub struct RemoveArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Member handle (owner of the trust store to update)
    #[arg(long = "member-handle", short = 'm', value_name = "MEMBER_HANDLE")]
    pub member_id: Option<String>,

    /// Key ID to remove
    pub kid: String,
}

#[derive(Args)]
pub struct PurgeArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Member handle (owner of the trust store to update)
    #[arg(long = "member-handle", short = 'm', value_name = "MEMBER_HANDLE")]
    pub member_id: Option<String>,

    /// Remove entries older than this duration (e.g. "180d")
    #[arg(long)]
    pub older_than: String,

    /// Skip confirmation prompt (required for non-interactive)
    #[arg(long, short = 'f')]
    pub force: bool,
}

pub fn run(args: TrustArgs) -> Result<(), Error> {
    match args.command {
        TrustCommands::List(args) => list::run(args),
        TrustCommands::Remove(args) => remove::run(args),
        TrustCommands::Purge(args) => purge::run(args),
    }
}
