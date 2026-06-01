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

use crate::cli::options::{
    AllowExpiredKeyOption, ForceOption, MemberHandleOption, SigningOutputOptions, WorkspaceOptions,
    WorkspaceOutputOptions,
};
use kapsaro_core::Error;

mod add;
mod list;
mod remove;
mod show;
mod verify;

#[derive(Args)]
#[command(disable_help_subcommand = true)]
pub(crate) struct MemberArgs {
    #[command(subcommand)]
    pub command: MemberCommands,
}

impl MemberArgs {
    pub(crate) fn debug_enabled(&self) -> bool {
        match &self.command {
            MemberCommands::Add(args) => args.common.debug.debug,
            MemberCommands::List(args) => args.common.debug.debug,
            MemberCommands::Remove(args) => args.common.debug.debug,
            MemberCommands::Show(args) => args.common.debug.debug,
            MemberCommands::Verify(args) => args.common.debug.debug,
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum MemberCommands {
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
pub(crate) struct AddArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: WorkspaceOptions,

    /// Path to PublicKey JSON file
    pub filename: PathBuf,

    #[command(flatten)]
    pub force: ForceOption,
}

#[derive(Args)]
pub(crate) struct ListArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: WorkspaceOutputOptions,
}

#[derive(Args)]
pub(crate) struct ShowArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: WorkspaceOutputOptions,

    /// Member handle to show
    #[arg(value_name = "MEMBER_HANDLE")]
    pub member_handle: String,
}

#[derive(Args)]
pub(crate) struct RemoveArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: WorkspaceOptions,

    #[command(flatten)]
    pub allow_expired_key: AllowExpiredKeyOption,

    /// Member handle to remove
    #[arg(value_name = "MEMBER_HANDLE")]
    pub member_handle: String,

    #[command(flatten)]
    pub force: ForceOption,
}

#[derive(Args)]
pub(crate) struct VerifyArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: SigningOutputOptions,

    #[command(flatten)]
    pub member: MemberHandleOption,

    /// Approve verified members and add to local trust store
    #[arg(long)]
    pub approve: bool,

    /// Member handles to verify (verifies all members if not specified)
    #[arg(value_name = "MEMBER_HANDLE")]
    pub member_handles: Vec<String>,
}

pub(crate) fn run(args: MemberArgs) -> Result<(), Error> {
    match args.command {
        MemberCommands::Add(args) => add::run(args),
        MemberCommands::List(args) => list::run(args),
        MemberCommands::Remove(args) => remove::run(args),
        MemberCommands::Show(args) => show::run(args),
        MemberCommands::Verify(args) => verify::run(args),
    }
}
