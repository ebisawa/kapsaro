// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! config command implementation

use clap::{Args, Subcommand};

use crate::cli::common::command::resolve_options;
use crate::cli::common::output::config::{
    print_config_list, print_config_set_result, print_config_unset_result, print_config_value,
};
use crate::cli::options::LocalOptions;
use secretenv_core::cli_api::app::config;
use secretenv_core::Error;

#[derive(Args)]
#[command(disable_help_subcommand = true)]
pub(crate) struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommands,
}

#[derive(Subcommand)]
pub(crate) enum ConfigCommands {
    /// Get configuration value
    Get(GetArgs),

    /// List all configurations
    List(ListArgs),

    /// Set configuration value
    Set(SetArgs),

    /// Remove configuration value
    Unset(UnsetArgs),
}

#[derive(Args)]
pub(crate) struct GetArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: LocalOptions,

    /// Configuration key
    pub key: String,
}

#[derive(Args)]
pub(crate) struct SetArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: LocalOptions,

    /// Configuration key
    pub key: String,

    /// Configuration value
    pub value: String,
}

#[derive(Args)]
pub(crate) struct UnsetArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: LocalOptions,

    /// Configuration key
    pub key: String,
}

#[derive(Args)]
pub(crate) struct ListArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: LocalOptions,
}

pub(crate) fn run(args: ConfigArgs) -> Result<(), Error> {
    match args.command {
        ConfigCommands::Get(args) => run_get(args),
        ConfigCommands::List(args) => run_list(args),
        ConfigCommands::Set(args) => run_set(args),
        ConfigCommands::Unset(args) => run_unset(args),
    }
}

fn run_get(args: GetArgs) -> Result<(), Error> {
    let options = resolve_options(&args.common);
    print_config_value(&config::resolve_config_value_command(&options, &args.key)?);
    Ok(())
}

fn run_set(args: SetArgs) -> Result<(), Error> {
    let options = resolve_options(&args.common);
    let result = config::set_config_command(&options, &args.key, &args.value)?;
    print_config_set_result(&result);
    Ok(())
}

fn run_unset(args: UnsetArgs) -> Result<(), Error> {
    let options = resolve_options(&args.common);
    let result = config::unset_config_command(&options, &args.key)?;
    print_config_unset_result(&result);
    Ok(())
}

fn run_list(args: ListArgs) -> Result<(), Error> {
    let options = resolve_options(&args.common);
    print_config_list(&config::list_config_command(&options)?);
    Ok(())
}
