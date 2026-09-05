// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! inspect command - Display encryption metadata without decryption
//!
//! Shows wrap information, recipients, and payload metadata for debugging
//! Supports encrypted artifact metadata inspection

use clap::Args;
use std::path::PathBuf;

use crate::cli::common::output::json::inspect::build_inspect_view;
use crate::cli::common::output::json::print_json_output;
use crate::cli::common::output::text::inspect::{
    build_inspect_output, format_inspect_output, print_inspect_banner,
};
use crate::cli::common::presentation::format_path_relative_to_cwd;
use crate::cli::options::OutputOptions;
use kapsaro_core::api::inspect::inspect_file;
use kapsaro_core::Result;

#[derive(Args)]
pub(crate) struct InspectArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: OutputOptions,

    /// Input file path
    pub input: PathBuf,
}

pub(crate) fn run(args: InspectArgs) -> Result<()> {
    let inspected = inspect_file(&args.input)?;

    if args.common.json.json {
        print_json_output(&build_inspect_view(&inspected.metadata))?;
    } else {
        print_inspect_banner(&format_path_relative_to_cwd(&args.input));
        let output = build_inspect_output(&inspected.metadata);
        print!("{}", format_inspect_output(&output));
    }
    Ok(())
}
