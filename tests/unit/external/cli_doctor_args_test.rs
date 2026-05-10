// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;

use secretenv::cli::{Cli, Commands};

#[test]
fn test_cli_doctor_parses_debug_option() {
    let cli = Cli::try_parse_from(["secretenv", "doctor", "--debug"]).unwrap();

    match cli.command {
        Commands::Doctor(args) => assert!(args.debug),
        _ => panic!("expected doctor command"),
    }
}
