// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CLI commands for kapsaro v3

// Common utilities (enabled for v3)
pub(crate) mod common;
pub(crate) mod error;
pub(crate) mod identity_prompt;
pub(crate) mod options;

// Active v3 commands
mod decrypt;
mod doctor;
mod encrypt;
mod get;
mod import;
mod init;
mod inspect;
mod join;
mod key;
mod list;
mod member;
mod registration;
mod rewrap;
mod run;
mod set;
mod trust;
mod unset;

mod config;

#[cfg(test)]
#[path = "../tests/unit/internal/stderr_color_guard.rs"]
pub(crate) mod stderr_color_guard;

use config::ConfigArgs;
use decrypt::DecryptArgs;
use doctor::DoctorArgs;
use get::GetArgs;
use import::ImportArgs;
use init::InitArgs;
use inspect::InspectArgs;
use join::JoinArgs;
use key::KeyArgs;
use list::ListArgs;
use member::MemberArgs;
use run::RunArgs;
use trust::TrustArgs;
use unset::UnsetArgs;

use clap::{Parser, Subcommand};

use crate::cli::common::env_mode::ensure_env_mode_command_allowed;
use kapsaro_core::cli_api::app::trust::CommandCapability;
use kapsaro_core::Error;
use tracing::debug;

#[derive(Parser)]
#[command(name = "kapsaro")]
#[command(version)]
#[command(disable_help_subcommand = true)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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

pub(crate) fn parse() -> Cli {
    match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = error::print_clap_error(&error);
            std::process::exit(code);
        }
    }
}

pub(crate) fn debug_enabled(cli: &Cli) -> bool {
    cli.command.debug_enabled()
}

pub(crate) fn run(cli: Cli) -> Result<i32, Error> {
    let capability = cli.command.capability();
    debug!("[CLI] command={}", capability.label());
    ensure_env_mode_command_allowed(capability)?;

    cli.command.run()
}

impl Commands {
    fn debug_enabled(&self) -> bool {
        match self {
            Commands::Config(_) => false,
            Commands::Decrypt(args) => args.common.debug.debug,
            Commands::Doctor(args) => args.common.debug.debug,
            Commands::Encrypt(args) => args.common.debug.debug,
            Commands::Get(args) => args.common.debug.debug,
            Commands::Import(args) => args.common.debug.debug,
            Commands::Init(args) => args.common.debug.debug,
            Commands::Inspect(args) => args.common.debug.debug,
            Commands::Join(args) => args.common.debug.debug,
            Commands::Key(args) => args.debug_enabled(),
            Commands::List(args) => args.common.debug.debug,
            Commands::Member(args) => args.debug_enabled(),
            Commands::Rewrap(args) => args.common.debug.debug,
            Commands::Run(args) => args.common.debug.debug,
            Commands::Set(args) => args.common.debug.debug,
            Commands::Trust(args) => args.debug_enabled(),
            Commands::Unset(args) => args.common.debug.debug,
        }
    }

    fn capability(&self) -> CommandCapability {
        match self {
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

    fn run(self) -> Result<i32, Error> {
        match self {
            Commands::Config(args) => config::run(args).map(|_| 0),
            Commands::Decrypt(args) => decrypt::run(args).map(|_| 0),
            Commands::Doctor(args) => doctor::run(args),
            Commands::Encrypt(args) => encrypt::run(args).map(|_| 0),
            Commands::Get(args) => get::run(args).map(|_| 0),
            Commands::Import(args) => import::run(args).map(|_| 0),
            Commands::Init(args) => init::run(args).map(|_| 0),
            Commands::Inspect(args) => inspect::run(args).map(|_| 0),
            Commands::Join(args) => join::run(args).map(|_| 0),
            Commands::Key(args) => key::run(args).map(|_| 0),
            Commands::List(args) => list::run(args).map(|_| 0),
            Commands::Member(args) => member::run(args).map(|_| 0),
            Commands::Rewrap(args) => rewrap::run(args).map(|_| 0),
            Commands::Run(args) => run::run(args),
            Commands::Set(args) => set::run(args).map(|_| 0),
            Commands::Trust(args) => trust::run(args).map(|_| 0),
            Commands::Unset(args) => unset::run(args).map(|_| 0),
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/internal/cli_args_test.rs"]
mod args_tests;
