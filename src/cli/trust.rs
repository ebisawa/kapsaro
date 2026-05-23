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
pub(crate) struct TrustArgs {
    #[command(subcommand)]
    pub command: TrustCommands,
}

impl TrustArgs {
    pub(crate) fn debug_enabled(&self) -> bool {
        match &self.command {
            TrustCommands::Keys(args) => args.debug_enabled(),
            TrustCommands::Recipients(args) => args.debug_enabled(),
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum TrustCommands {
    /// Manage known keys in local trust store
    Keys(KeysArgs),

    /// Manage approved artifact recipient sets in local trust store
    Recipients(RecipientsArgs),
}

#[derive(Args)]
pub(crate) struct KeysArgs {
    #[command(subcommand)]
    pub command: KeyTrustCommands,
}

impl KeysArgs {
    fn debug_enabled(&self) -> bool {
        match &self.command {
            KeyTrustCommands::List(args) => args.common.debug.debug,
            KeyTrustCommands::Remove(args) => args.common.debug.debug,
            KeyTrustCommands::Purge(args) => args.common.debug.debug,
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum KeyTrustCommands {
    /// List known keys in local trust store
    List(ListArgs),

    /// Remove a known key from local trust store
    Remove(RemoveArgs),

    /// Purge old known keys from local trust store
    Purge(PurgeArgs),
}

#[derive(Args)]
pub(crate) struct RecipientsArgs {
    #[command(subcommand)]
    pub command: RecipientTrustCommands,
}

impl RecipientsArgs {
    fn debug_enabled(&self) -> bool {
        match &self.command {
            RecipientTrustCommands::List(args) => args.common.debug.debug,
            RecipientTrustCommands::Remove(args) => args.common.debug.debug,
            RecipientTrustCommands::Purge(args) => args.common.debug.debug,
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum RecipientTrustCommands {
    /// List approved recipient sets in local trust store
    List(ListArgs),

    /// Remove an approved recipient set from local trust store
    Remove(RecipientRemoveArgs),

    /// Purge old recipient set approvals from local trust store
    Purge(PurgeArgs),
}

#[derive(Args)]
pub(crate) struct ListArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: LocalOutputOptions,

    #[command(flatten)]
    pub member: MemberHandleOption,
}

#[derive(Args)]
pub(crate) struct RemoveArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningOptions,

    #[command(flatten)]
    pub member: MemberHandleOption,

    /// Key ID to remove
    pub kid: String,
}

#[derive(Args)]
pub(crate) struct PurgeArgs {
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
pub(crate) struct RecipientRemoveArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningOptions,

    #[command(flatten)]
    pub member: MemberHandleOption,

    /// Secret identifier to remove
    pub sid: String,
}

pub(crate) fn run(args: TrustArgs) -> Result<(), Error> {
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
