// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;

use secretenv::cli::{Cli, Commands};

#[test]
fn test_cli_set_parses_member_id_option() {
    let cli =
        Cli::try_parse_from(["secretenv", "set", "FOO", "BAR", "--member-id", "ebisawa"]).unwrap();

    match cli.command {
        Commands::Set(args) => {
            assert_eq!(args.member_id.as_deref(), Some("ebisawa"));
        }
        _ => panic!("expected set command"),
    }
}

#[test]
fn test_cli_member_verify_parses_member_id_option() {
    let cli = Cli::try_parse_from([
        "secretenv",
        "member",
        "verify",
        "--member-id",
        "alice@example.com",
        "bob@example.com",
    ]);

    assert!(cli.is_ok());

    let cli = cli.unwrap();
    assert!(matches!(cli.command, Commands::Member(_)));
}

#[test]
fn test_cli_trust_remove_parses_member_id_option() {
    let cli = Cli::try_parse_from([
        "secretenv",
        "trust",
        "remove",
        "--member-id",
        "alice@example.com",
        "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0",
    ])
    .unwrap();

    assert!(matches!(cli.command, Commands::Trust(_)));
}

#[test]
fn test_cli_trust_purge_parses_member_id_option() {
    let cli = Cli::try_parse_from([
        "secretenv",
        "trust",
        "purge",
        "--member-id",
        "alice@example.com",
        "--older-than",
        "1d",
    ])
    .unwrap();

    assert!(matches!(cli.command, Commands::Trust(_)));
}
