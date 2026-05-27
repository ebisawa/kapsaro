// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;

use super::{Cli, Commands};

fn parse_error(args: &[&str]) -> clap::Error {
    match Cli::try_parse_from(args) {
        Ok(_) => panic!("command should reject option"),
        Err(error) => error,
    }
}

#[test]
fn test_cli_doctor_parses_debug_option() {
    let cli = Cli::try_parse_from(["secretenv", "doctor", "--debug"]).unwrap();

    match cli.command {
        Commands::Doctor(args) => assert!(args.common.debug.debug),
        _ => panic!("expected doctor command"),
    }
}

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
        &["secretenv", "list", "--ssh-keygen"][..],
        &["secretenv", "list", "--member-handle", "alice@example.com"][..],
        &["secretenv", "list", "--allow-expired-key"][..],
        &["secretenv", "set", "--ssh-keygen", "KEY", "VALUE"][..],
        &["secretenv", "run", "--ssh-keygen", "--", "env"][..],
        &["secretenv", "rewrap", "--ssh-keygen"][..],
    ] {
        Cli::try_parse_from(args).expect("command should accept SSH signing options");
    }
}

#[test]
fn test_allow_weak_password_is_limited_to_private_key_export() {
    let err = parse_error(&[
        "secretenv",
        "key",
        "export",
        "--allow-weak-password",
        "--out",
        "key.json",
    ]);
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);

    Cli::try_parse_from([
        "secretenv",
        "key",
        "export",
        "--private",
        "--allow-weak-password",
        "--stdout",
        "--member-handle",
        "alice@example.com",
    ])
    .expect("private key export should accept --allow-weak-password");
}

#[test]
fn test_trust_purge_accepts_force_short_option() {
    for args in [
        &[
            "secretenv",
            "trust",
            "keys",
            "purge",
            "--older-than",
            "1d",
            "-f",
        ][..],
        &[
            "secretenv",
            "trust",
            "recipients",
            "purge",
            "--older-than",
            "1d",
            "-f",
        ][..],
    ] {
        Cli::try_parse_from(args).expect("trust purge should accept -f");
    }
}
