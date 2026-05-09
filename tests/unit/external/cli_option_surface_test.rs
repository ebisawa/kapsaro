// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;

use secretenv::cli::Cli;

fn parse_error(args: &[&str]) -> clap::Error {
    match Cli::try_parse_from(args) {
        Ok(_) => panic!("command should reject option"),
        Err(error) => error,
    }
}

#[test]
fn test_workspace_remains_subcommand_option() {
    let err = parse_error(&["secretenv", "--workspace", ".secretenv", "list"]);

    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

#[test]
fn test_quiet_is_limited_to_status_message_commands() {
    for args in [
        &["secretenv", "get", "--quiet", "KEY"][..],
        &["secretenv", "list", "--quiet"][..],
        &["secretenv", "config", "list", "--quiet"][..],
        &["secretenv", "trust", "keys", "list", "--quiet"][..],
    ] {
        let err = parse_error(args);
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    for args in [
        &["secretenv", "encrypt", "--quiet", "plain.txt"][..],
        &["secretenv", "decrypt", "--quiet", "secret.enc", "--stdout"][..],
        &["secretenv", "set", "--quiet", "KEY", "VALUE"][..],
        &["secretenv", "unset", "--quiet", "--force", "KEY"][..],
        &["secretenv", "import", "--quiet", ".env"][..],
        &["secretenv", "rewrap", "--quiet"][..],
    ] {
        Cli::try_parse_from(args).expect("command should accept --quiet");
    }
}

#[test]
fn test_ssh_options_are_limited_to_signing_commands() {
    for args in [
        &["secretenv", "doctor", "--ssh-identity", "id_ed25519"][..],
        &["secretenv", "inspect", "--ssh-keygen", "secret.enc"][..],
        &["secretenv", "member", "list", "--ssh-agent"][..],
        &["secretenv", "config", "list", "--ssh-keygen"][..],
    ] {
        let err = parse_error(args);
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    for args in [
        &["secretenv", "encrypt", "--ssh-keygen", "plain.txt"][..],
        &[
            "secretenv",
            "decrypt",
            "--ssh-identity",
            "id_ed25519",
            "secret.enc",
            "--stdout",
        ][..],
        &["secretenv", "get", "--ssh-agent", "KEY"][..],
        &["secretenv", "set", "--ssh-keygen", "KEY", "VALUE"][..],
        &["secretenv", "run", "--ssh-keygen", "--", "env"][..],
        &["secretenv", "rewrap", "--ssh-keygen"][..],
    ] {
        Cli::try_parse_from(args).expect("command should accept SSH signing options");
    }
}
