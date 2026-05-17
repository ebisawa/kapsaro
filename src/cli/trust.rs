// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! trust subcommand: local trust store management.

use clap::{Args, Subcommand};

use crate::cli::options::{ForceOption, LocalOutputOptions, MemberHandleOption, SigningOptions};
use secretenv_core::Error;

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
    /// Manage known keys in local trust store
    Keys(KeysArgs),

    /// Manage approved artifact recipient sets in local trust store
    Recipients(RecipientsArgs),
}

#[derive(Args)]
pub struct KeysArgs {
    #[command(subcommand)]
    pub command: KeyTrustCommands,
}

#[derive(Subcommand)]
pub enum KeyTrustCommands {
    /// List known keys in local trust store
    List(ListArgs),

    /// Remove a known key from local trust store
    Remove(RemoveArgs),

    /// Purge old known keys from local trust store
    Purge(PurgeArgs),
}

#[derive(Args)]
pub struct RecipientsArgs {
    #[command(subcommand)]
    pub command: RecipientTrustCommands,
}

#[derive(Subcommand)]
pub enum RecipientTrustCommands {
    /// List approved recipient sets in local trust store
    List(ListArgs),

    /// Remove an approved recipient set from local trust store
    Remove(RecipientRemoveArgs),

    /// Purge old recipient set approvals from local trust store
    Purge(PurgeArgs),
}

#[derive(Args)]
pub struct ListArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: LocalOutputOptions,

    #[command(flatten)]
    pub member: MemberHandleOption,
}

#[derive(Args)]
pub struct RemoveArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningOptions,

    #[command(flatten)]
    pub member: MemberHandleOption,

    /// Key ID to remove
    pub kid: String,
}

#[derive(Args)]
pub struct PurgeArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningOptions,

    #[command(flatten)]
    pub member: MemberHandleOption,

    /// Remove entries older than this duration (e.g. "180d")
    #[arg(long)]
    pub older_than: String,

    #[command(flatten)]
    pub force: ForceOption,
}

#[derive(Args)]
pub struct RecipientRemoveArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningOptions,

    #[command(flatten)]
    pub member: MemberHandleOption,

    /// Secret identifier to remove
    pub sid: String,
}

pub fn run(args: TrustArgs) -> Result<(), Error> {
    match args.command {
        TrustCommands::Keys(args) => run_keys(args),
        TrustCommands::Recipients(args) => run_recipients(args),
    }
}

fn run_keys(args: KeysArgs) -> Result<(), Error> {
    match args.command {
        KeyTrustCommands::List(args) => list::run_keys(args),
        KeyTrustCommands::Remove(args) => remove::run_key(args),
        KeyTrustCommands::Purge(args) => purge::run_keys(args),
    }
}

fn run_recipients(args: RecipientsArgs) -> Result<(), Error> {
    match args.command {
        RecipientTrustCommands::List(args) => list::run_recipients(args),
        RecipientTrustCommands::Remove(args) => remove::run_recipient(args),
        RecipientTrustCommands::Purge(args) => purge::run_recipients(args),
    }
}
