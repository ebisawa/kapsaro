// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! secretenv CLI entry point.

mod cli;

#[cfg(test)]
#[path = "../tests/test_utils/internal_cli.rs"]
mod test_utils;

#[cfg(test)]
#[path = "../tests/test_utils/context_options.rs"]
mod app_test_utils;

use tracing_subscriber::{fmt, EnvFilter};

fn main() {
    let cli = cli::parse();
    let filter = if cli::debug_enabled(&cli) {
        EnvFilter::new("debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };
    fmt().with_env_filter(filter).with_target(false).init();

    match cli::run(cli) {
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err(e) => {
            cli::error::print_error(&e);
            std::process::exit(1);
        }
    }
}
