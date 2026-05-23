// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! inspect command - Display encryption metadata without decryption
//!
//! Shows wrap information, recipients, and payload metadata for debugging
//! Supports encrypted artifact metadata inspection

use clap::Args;
use std::path::PathBuf;

use crate::cli::common::command::resolve_options;
use crate::cli::common::output::json::print_json_output;
use crate::cli::common::output::text::inspect::{
    format_inspect_command_output, print_inspect_banner,
};
use crate::cli::options::WorkspaceOutputOptions;
use secretenv_core::cli_api::app::file::inspect::execute_inspect_file_command;
use secretenv_core::Result;

#[derive(Args)]
pub(crate) struct InspectArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: WorkspaceOutputOptions,

    /// Input file path
    pub input: PathBuf,
}

pub(crate) fn run(args: InspectArgs) -> Result<()> {
    let options = resolve_options(&args.common);
    let prepared = execute_inspect_file_command(&options, &args.input)?;

    if args.common.json.json {
        print_json_output(&prepared.output)?;
    } else {
        print_inspect_banner(&prepared.input_display);
        print!("{}", format_inspect_command_output(&prepared));
    }
    Ok(())
}
