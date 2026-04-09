// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! secretenv CLI entry point.
//!
//! Phase 2.7: Re-enabled with decrypt command

use secretenv::cli;
use tracing_subscriber::{fmt, EnvFilter};

fn main() {
    let verbose = std::env::args().any(|arg| arg == "--verbose" || arg == "-v");
    let filter = if verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };
    fmt().with_env_filter(filter).with_target(false).init();

    if let Err(e) = cli::run() {
        cli::error::print_error(&e);
        std::process::exit(1);
    }
}
