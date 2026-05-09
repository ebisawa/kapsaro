// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! inspect command - Display encryption metadata without decryption
//!
//! Shows wrap information, recipients, and payload metadata for debugging
//! Supports both kv-enc v6 and file-enc v5 formats

use clap::Args;
use std::path::PathBuf;

use crate::app::file::inspect::execute_inspect_file_command;
use crate::cli::common::command::resolve_options;
use crate::cli::common::output::text::inspect::{
    format_inspect_command_output, print_inspect_banner,
};
use crate::cli::options::CommonOptions;
use crate::Result;

#[derive(Args)]
pub struct InspectArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Input file path
    pub input: PathBuf,
}

pub fn run(args: InspectArgs) -> Result<()> {
    let options = resolve_options(&args.common);
    let prepared = execute_inspect_file_command(&options, &args.input)?;

    print_inspect_banner(&prepared.input_display);
    print!("{}", format_inspect_command_output(&prepared));
    Ok(())
}
