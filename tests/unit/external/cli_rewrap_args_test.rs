// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;

use secretenv::cli::{Cli, Commands};

#[test]
fn test_cli_rewrap_parses_target_options() {
    let cli = Cli::try_parse_from([
        "secretenv",
        "rewrap",
        "--target",
        "../certs/ca.pem.encrypted",
        "--target",
        "/tmp/app.env.encrypted",
    ])
    .unwrap();

    match cli.command {
        Commands::Rewrap(args) => {
            assert_eq!(args.targets.len(), 2);
            assert_eq!(
                args.targets[0].to_string_lossy(),
                "../certs/ca.pem.encrypted"
            );
            assert_eq!(args.targets[1].to_string_lossy(), "/tmp/app.env.encrypted");
        }
        _ => panic!("expected rewrap command"),
    }
}
