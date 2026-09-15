// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;

use super::{Cli, Commands};
use crate::cli::member::MemberCommands;
use crate::cli::options::{CommonOptions, ToCommonOptions};

const GLOBAL_COMMANDS: &[(&[&str], &[&str])] = &[
    (&["init"], &[]),
    (&["join"], &[]),
    (&["encrypt"], &["input.txt"]),
    (&["decrypt"], &["input.fileenc", "--stdout"]),
    (&["get"], &["KEY"]),
    (&["set"], &["KEY", "VALUE"]),
    (&["unset"], &["KEY"]),
    (&["list"], &[]),
    (&["import"], &["input.env"]),
    (&["run"], &["--", "true"]),
    (&["rewrap"], &[]),
    (&["member", "list"], &[]),
    (&["member", "add"], &["member.json"]),
    (&["member", "remove"], &["alice@example.com"]),
    (&["member", "show"], &["alice@example.com"]),
    (&["member", "verify"], &[]),
];

fn global_arguments<'a>(
    command: &'a [&'a str],
    arguments: &'a [&'a str],
    options: &'a [&'a str],
) -> Vec<&'a str> {
    std::iter::once("kapsaro")
        .chain(command.iter().copied())
        .chain(options.iter().copied())
        .chain(arguments.iter().copied())
        .collect()
}

fn workspace_options(cli: &Cli) -> CommonOptions {
    match &cli.command {
        Commands::Init(args) => args.common.to_common_options(),
        Commands::Join(args) => args.common.to_common_options(),
        Commands::Encrypt(args) => args.common.to_common_options(),
        Commands::Decrypt(args) => args.common.to_common_options(),
        Commands::Get(args) => args.common.to_common_options(),
        Commands::Set(args) => args.common.to_common_options(),
        Commands::Unset(args) => args.common.to_common_options(),
        Commands::List(args) => args.common.to_common_options(),
        Commands::Import(args) => args.common.to_common_options(),
        Commands::Run(args) => args.common.to_common_options(),
        Commands::Rewrap(args) => args.common.to_common_options(),
        Commands::Member(args) => match &args.command {
            MemberCommands::List(args) => args.common.to_common_options(),
            MemberCommands::Add(args) => args.common.to_common_options(),
            MemberCommands::Remove(args) => args.common.to_common_options(),
            MemberCommands::Show(args) => args.common.to_common_options(),
            MemberCommands::Verify(args) => args.common.to_common_options(),
        },
        _ => panic!("expected a workspace command"),
    }
}

#[test]
fn test_all_workspace_commands_resolve_both_global_spellings() {
    for &(command, arguments) in GLOBAL_COMMANDS {
        for flag in ["--global", "-g"] {
            let options = [flag];
            let args = global_arguments(command, arguments, &options);
            let cli =
                Cli::try_parse_from(&args).unwrap_or_else(|error| panic!("{args:?}: {error}"));
            let options = workspace_options(&cli);
            assert!(options.global, "{args:?}");
            assert!(options.workspace.is_none(), "{args:?}");
        }
    }
}

#[test]
fn test_all_global_command_spellings_enforce_explicit_workspace_conflicts() {
    for &(command, arguments) in GLOBAL_COMMANDS {
        for flag in ["--global", "-g"] {
            let options = [flag, "--workspace", "workspace"];
            let args = global_arguments(command, arguments, &options);
            assert_eq!(
                parse_error(&args).kind(),
                clap::error::ErrorKind::ArgumentConflict,
                "{args:?}"
            );
        }
    }
}

#[test]
#[serial_test::serial]
fn test_all_global_command_spellings_validate_home_before_local_state_creation() {
    use crate::cli::common::context::CliContext;
    let _guard = crate::test_utils::EnvGuard::new(&["HOME"]);
    let local = tempfile::TempDir::new().unwrap();
    for home in [None, Some(""), Some("relative-home")] {
        match home {
            Some(home) => std::env::set_var("HOME", home),
            None => std::env::remove_var("HOME"),
        }
        for &(command, arguments) in GLOBAL_COMMANDS {
            for flag in ["--global", "-g"] {
                let flags = [flag];
                let args = global_arguments(command, arguments, &flags);
                let cli =
                    Cli::try_parse_from(&args).unwrap_or_else(|error| panic!("{args:?}: {error}"));
                let mut options = workspace_options(&cli);
                options.home = Some(local.path().join("local-state"));
                let error = CliContext::resolve(&options)
                    .err()
                    .expect("invalid HOME must fail");
                assert_eq!(
                    error.kind(),
                    kapsaro_core::ErrorKind::InvalidArgument,
                    "{args:?}"
                );
            }
        }
    }
    assert_eq!(std::fs::read_dir(local.path()).unwrap().count(), 0);
}

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
