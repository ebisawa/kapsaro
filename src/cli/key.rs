// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! key command implementation
//!
//! Key management commands:
//! - key new: Generate new key pair
//! - key list: List keys
//! - key activate: Activate a key
//! - key remove: Remove a key
//! - key export: Export public key

use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::cli::options::CommonOptions;
use crate::Result;

// Submodule declarations
pub(crate) mod common;
mod list;
mod new;
mod operations;

#[derive(Args)]
#[command(disable_help_subcommand = true)]
pub struct KeyArgs {
    #[command(subcommand)]
    pub command: KeyCommand,
}

#[derive(Subcommand)]
pub enum KeyCommand {
    /// Activate a key
    Activate(ActivateArgs),
    /// Export a key
    Export(ExportArgs),
    /// List keys
    List(ListArgs),
    /// Generate new key pair
    New(NewArgs),
    /// Remove a key
    Remove(RemoveArgs),
}

#[derive(Args)]
pub struct NewArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Expiration date (RFC3339 format)
    #[arg(long, conflicts_with = "valid_for")]
    pub expires_at: Option<String>,

    /// GitHub username for identity binding
    #[arg(long)]
    pub github_user: Option<String>,

    /// Member handle to use
    #[arg(long = "member-handle", short = 'm', value_name = "MEMBER_HANDLE")]
    pub member_id: Option<String>,

    /// Do not activate the generated key
    #[arg(long)]
    pub no_activate: bool,

    /// Validity period (e.g., 1y, 365d, 6m)
    #[arg(long)]
    pub valid_for: Option<String>,
}

#[derive(Args)]
pub struct ListArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Member handle to use
    #[arg(long = "member-handle", short = 'm', value_name = "MEMBER_HANDLE")]
    pub member_id: Option<String>,
}

#[derive(Args)]
pub struct ActivateArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Member handle to use
    #[arg(long = "member-handle", short = 'm', value_name = "MEMBER_HANDLE")]
    pub member_id: Option<String>,

    /// Key ID to activate [default: newest valid key]
    pub kid: Option<String>,
}

#[derive(Args)]
pub struct RemoveArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Force removal of active key
    #[arg(long, short = 'f')]
    pub force: bool,

    /// Member handle to use
    #[arg(long = "member-handle", short = 'm', value_name = "MEMBER_HANDLE")]
    pub member_id: Option<String>,

    /// Key ID to remove
    pub kid: String,
}

#[derive(Args)]
#[command(override_usage = "\
secretenv key export [OPTIONS] -o <OUT> [KID]
       secretenv key export --private [OPTIONS] [--stdout] [KID]")]
pub struct ExportArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Member handle to use
    #[arg(long = "member-handle", short = 'm', value_name = "MEMBER_HANDLE")]
    pub member_id: Option<String>,

    /// Key ID to export [default: active key]
    pub kid: Option<String>,

    /// Output file path
    #[arg(long, short = 'o', required_unless_present = "private")]
    pub out: Option<PathBuf>,

    /// Write exported private key to stdout
    #[arg(long, requires = "private", conflicts_with = "out")]
    pub stdout: bool,

    /// Export password-protected portable private key
    #[arg(long)]
    pub private: bool,
}

pub fn run(args: KeyArgs) -> Result<()> {
    match args.command {
        KeyCommand::Activate(args) => operations::run_activate(args),
        KeyCommand::Export(args) => {
            if args.private {
                operations::run_export_private(args)
            } else {
                operations::run_export(args)
            }
        }
        KeyCommand::List(args) => list::run(args),
        KeyCommand::New(args) => new::run(args),
        KeyCommand::Remove(args) => operations::run_remove(args),
    }
}
