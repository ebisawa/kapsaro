// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CLI commands for secretenv v3

// Common utilities (enabled for v3)
pub(crate) mod common;
pub mod error;
pub(crate) mod identity_prompt;
pub mod options;

// Active v3 commands
mod decrypt;
mod doctor;
pub mod encrypt;
mod get;
mod import;
mod init;
mod inspect;
mod join;
mod key;
mod list;
mod member;
mod registration;
pub mod rewrap;
mod run;
pub mod set;
mod trust;
mod unset;

mod config;

pub use config::ConfigArgs;
pub use decrypt::DecryptArgs;
pub use doctor::DoctorArgs;
pub use get::GetArgs;
pub use import::ImportArgs;
pub use init::InitArgs;
pub use inspect::InspectArgs;
pub use join::JoinArgs;
pub use key::KeyArgs;
pub use list::ListArgs;
pub use member::MemberArgs;
pub use run::RunArgs;
pub use trust::TrustArgs;
pub use unset::UnsetArgs;

use clap::{Parser, Subcommand};

use crate::app::trust::CommandCapability;
use crate::cli::common::env_mode::ensure_env_mode_command_allowed;
use crate::Error;

#[derive(Parser)]
#[command(name = "secretenv")]
#[command(version)]
#[command(disable_help_subcommand = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Configuration management
    Config(ConfigArgs),

    /// Decrypt a file
    Decrypt(DecryptArgs),

    /// Diagnose workspace and local state
    Doctor(DoctorArgs),

    /// Encrypt a file
    Encrypt(encrypt::EncryptArgs),

    /// Get a secret value
    Get(GetArgs),

    /// Import secrets from .env file
    Import(ImportArgs),

    /// Initialize workspace
    Init(InitArgs),

    /// Inspect encrypted file metadata
    Inspect(InspectArgs),

    /// Join an existing workspace
    Join(JoinArgs),

    /// Key management
    Key(KeyArgs),

    /// List all secrets
    List(ListArgs),

    /// Member management
    Member(MemberArgs),

    /// Re-encrypt secrets for updated members
    Rewrap(rewrap::RewrapArgs),

    /// Run command with decrypted environment variables
    Run(RunArgs),

    /// Set a secret value
    Set(set::SetArgs),

    /// Trust store management
    Trust(TrustArgs),

    /// Remove a secret
    Unset(UnsetArgs),
}

pub fn run() -> Result<(), Error> {
    let cli = Cli::parse();
    ensure_env_mode_command_allowed(command_capability(&cli.command))?;

    match cli.command {
        Commands::Config(args) => config::run(args),
        Commands::Decrypt(args) => decrypt::run(args),
        Commands::Doctor(args) => doctor::run(args),
        Commands::Encrypt(args) => encrypt::run(args),
        Commands::Get(args) => get::run(args),
        Commands::Import(args) => import::run(args),
        Commands::Init(args) => init::run(args),
        Commands::Inspect(args) => inspect::run(args),
        Commands::Join(args) => join::run(args),
        Commands::Key(args) => key::run(args),
        Commands::List(args) => list::run(args),
        Commands::Member(args) => member::run(args),
        Commands::Rewrap(args) => rewrap::run(args),
        Commands::Run(args) => run::run(args),
        Commands::Set(args) => set::run(args),
        Commands::Trust(args) => trust::run(args),
        Commands::Unset(args) => unset::run(args),
    }
}

fn command_capability(command: &Commands) -> CommandCapability {
    match command {
        Commands::Config(_) => CommandCapability::Config,
        Commands::Decrypt(_) => CommandCapability::Decrypt,
        Commands::Doctor(_) => CommandCapability::Doctor,
        Commands::Encrypt(_) => CommandCapability::Encrypt,
        Commands::Get(_) => CommandCapability::Get,
        Commands::Import(_) => CommandCapability::Import,
        Commands::Init(_) => CommandCapability::Init,
        Commands::Inspect(_) => CommandCapability::Inspect,
        Commands::Join(_) => CommandCapability::Join,
        Commands::Key(_) => CommandCapability::Key,
        Commands::List(_) => CommandCapability::List,
        Commands::Member(_) => CommandCapability::Member,
        Commands::Rewrap(_) => CommandCapability::Rewrap,
        Commands::Run(_) => CommandCapability::Run,
        Commands::Set(_) => CommandCapability::Set,
        Commands::Trust(_) => CommandCapability::Trust,
        Commands::Unset(_) => CommandCapability::Unset,
    }
}
