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
    let cli = Cli::try_parse_from(["kapsaro", "doctor", "--debug"]).unwrap();

    match cli.command {
        Commands::Doctor(args) => assert!(args.common.debug.debug),
        _ => panic!("expected doctor command"),
    }
}

#[test]
fn test_cli_rewrap_parses_target_options() {
    let cli = Cli::try_parse_from([
        "kapsaro",
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
    let err = parse_error(&["kapsaro", "--workspace", ".kapsaro", "list"]);

    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

#[test]
fn test_quiet_is_limited_to_status_message_commands() {
    for args in [
        &["kapsaro", "get", "--quiet", "KEY"][..],
        &["kapsaro", "list", "--quiet"][..],
        &["kapsaro", "config", "list", "--quiet"][..],
        &["kapsaro", "trust", "keys", "list", "--quiet"][..],
    ] {
        let err = parse_error(args);
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    for args in [
        &["kapsaro", "encrypt", "--quiet", "plain.txt"][..],
        &["kapsaro", "decrypt", "--quiet", "secret.enc", "--stdout"][..],
        &["kapsaro", "set", "--quiet", "KEY", "VALUE"][..],
        &["kapsaro", "unset", "--quiet", "--force", "KEY"][..],
        &["kapsaro", "import", "--quiet", ".env"][..],
        &["kapsaro", "rewrap", "--quiet"][..],
    ] {
        Cli::try_parse_from(args).expect("command should accept --quiet");
    }
}

#[test]
fn test_ssh_options_are_limited_to_signing_commands() {
    for args in [
        &["kapsaro", "doctor", "--ssh-identity", "id_ed25519"][..],
        &["kapsaro", "inspect", "--ssh-keygen", "secret.enc"][..],
        &["kapsaro", "member", "list", "--ssh-agent"][..],
        &["kapsaro", "config", "list", "--ssh-keygen"][..],
    ] {
        let err = parse_error(args);
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    for args in [
        &["kapsaro", "encrypt", "--ssh-keygen", "plain.txt"][..],
        &[
            "kapsaro",
            "decrypt",
            "--ssh-identity",
            "id_ed25519",
            "secret.enc",
            "--stdout",
        ][..],
        &["kapsaro", "get", "--ssh-agent", "KEY"][..],
        &["kapsaro", "list", "--ssh-keygen"][..],
        &["kapsaro", "list", "--member-handle", "alice@example.com"][..],
        &["kapsaro", "list", "--allow-expired-key"][..],
        &["kapsaro", "set", "--ssh-keygen", "KEY", "VALUE"][..],
        &["kapsaro", "run", "--ssh-keygen", "--", "env"][..],
        &["kapsaro", "rewrap", "--ssh-keygen"][..],
    ] {
        Cli::try_parse_from(args).expect("command should accept SSH signing options");
    }
}

#[test]
fn test_allow_non_member_is_limited_to_non_member_review_commands() {
    for args in [
        &["kapsaro", "run", "--allow-non-member", "--", "env"][..],
        &["kapsaro", "set", "--allow-non-member", "KEY", "VALUE"][..],
        &["kapsaro", "encrypt", "--allow-non-member", "plain.txt"][..],
        &["kapsaro", "inspect", "--allow-non-member", "secret.enc"][..],
    ] {
        let err = parse_error(args);
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    for args in [
        &[
            "kapsaro",
            "decrypt",
            "--allow-non-member",
            "secret.enc",
            "--stdout",
        ][..],
        &["kapsaro", "get", "--allow-non-member", "KEY"][..],
        &["kapsaro", "list", "--allow-non-member"][..],
        &["kapsaro", "rewrap", "--allow-non-member"][..],
    ] {
        Cli::try_parse_from(args).expect("command should accept --allow-non-member");
    }
}

#[test]
fn test_allow_weak_password_is_limited_to_private_key_export() {
    let err = parse_error(&[
        "kapsaro",
        "key",
        "export",
        "--allow-weak-password",
        "--out",
        "key.json",
    ]);
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);

    Cli::try_parse_from([
        "kapsaro",
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
            "kapsaro",
            "trust",
            "keys",
            "purge",
            "--older-than",
            "1d",
            "-f",
        ][..],
        &[
            "kapsaro",
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
