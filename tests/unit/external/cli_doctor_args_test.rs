// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;

use secretenv::cli::{Cli, Commands};

#[test]
fn test_cli_doctor_parses_required_surface() {
    let cli = Cli::try_parse_from([
        "secretenv",
        "doctor",
        "--workspace",
        ".secretenv",
        "--home",
        ".secret-home",
        "--member-handle",
        "alice@example.com",
        "--verbose",
    ])
    .unwrap();

    match cli.command {
        Commands::Doctor(args) => {
            assert_eq!(args.workspace.unwrap().to_string_lossy(), ".secretenv");
            assert_eq!(args.home.unwrap().to_string_lossy(), ".secret-home");
            assert_eq!(args.member_handle.as_deref(), Some("alice@example.com"));
            assert!(args.verbose);
            assert!(!args.debug);
        }
        _ => panic!("expected doctor command"),
    }
}

#[test]
fn test_cli_doctor_parses_debug_option() {
    let cli = Cli::try_parse_from(["secretenv", "doctor", "--debug"]).unwrap();

    match cli.command {
        Commands::Doctor(args) => assert!(args.debug),
        _ => panic!("expected doctor command"),
    }
}

#[test]
fn test_cli_doctor_parses_json_option() {
    let cli = Cli::try_parse_from(["secretenv", "doctor", "--json"]).unwrap();

    match cli.command {
        Commands::Doctor(args) => assert!(args.json),
        _ => panic!("expected doctor command"),
    }
}
