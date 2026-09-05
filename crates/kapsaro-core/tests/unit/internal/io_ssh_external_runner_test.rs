// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the shared runner that launches external SSH commands.
//! Covers the child environment, the agent socket policy, and stdin wiring.

use super::SshCommandRunner;
use crate::io::ssh::SshError;
use crate::test_utils::EnvGuard;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use tempfile::TempDir;

/// Programs that the test suite never writes. Execing a file this process has
/// open for writing fails with ETXTBSY once a concurrent fork inherits the
/// descriptor, which is why these tests use system binaries instead of
/// generated scripts.
const ENV_DUMP_PROGRAM: &str = "/usr/bin/env";
const ECHO_STDIN_PROGRAM: &str = "/bin/cat";
const REFUSING_STDIN_PROGRAM: &str = "/bin/sh";

const AGENT_SOCKET: &str = "/tmp/kapsaro-test-agent.sock";

fn no_args() -> std::iter::Empty<&'static str> {
    std::iter::empty()
}

fn spawn_error(e: std::io::Error) -> SshError {
    SshError::build_operation_failed_error_with_source("Failed to execute test program", e)
}

/// Socket resolution reads `~/.ssh/config` before falling back to the
/// environment, so `HOME` has to point somewhere without a config.
fn guard_with_empty_home(keys: &[&str]) -> (EnvGuard, TempDir) {
    let guard = EnvGuard::new(keys);
    let fake_home = TempDir::new().unwrap();
    std::env::set_var("HOME", fake_home.path());
    (guard, fake_home)
}

fn env_delta(command: &std::process::Command) -> BTreeMap<String, Option<String>> {
    command
        .get_envs()
        .map(|(key, value)| {
            (
                key.to_string_lossy().into_owned(),
                value.map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .collect()
}

/// The agent socket is the only value the runner adds, and every KAPSARO
/// variable is scheduled for removal so no credential reaches the child.
#[test]
#[serial_test::serial]
fn test_command_removes_kapsaro_env_and_sets_only_the_agent_socket() {
    let (_guard, _home) = guard_with_empty_home(&["HOME", "SSH_AUTH_SOCK", "KAPSARO_PRIVATE_KEY"]);
    std::env::set_var("SSH_AUTH_SOCK", AGENT_SOCKET);
    std::env::set_var("KAPSARO_PRIVATE_KEY", "sensitive");

    let command = SshCommandRunner::optional_agent(
        "/usr/bin/ssh-keygen",
        Some(std::path::PathBuf::from(AGENT_SOCKET)),
    )
    .command()
    .unwrap();
    let delta = env_delta(&command);

    assert_eq!(command.get_program(), OsStr::new("/usr/bin/ssh-keygen"));
    assert_eq!(delta.get("KAPSARO_PRIVATE_KEY"), Some(&None));
    let assigned: Vec<&String> = delta
        .iter()
        .filter(|(_, value)| value.is_some())
        .map(|(key, _)| key)
        .collect();
    assert_eq!(assigned, vec!["SSH_AUTH_SOCK"]);
    assert_eq!(delta["SSH_AUTH_SOCK"], Some(AGENT_SOCKET.to_string()));
}

/// A command that signs with a key file schedules the inherited agent socket
/// for removal. Leaving the value out of the child environment would not be
/// enough, because the child inherits this process's own `SSH_AUTH_SOCK`.
#[test]
#[serial_test::serial]
fn test_command_without_agent_removes_the_inherited_agent_socket() {
    let (_guard, _home) = guard_with_empty_home(&["HOME", "SSH_AUTH_SOCK"]);
    std::env::set_var("SSH_AUTH_SOCK", AGENT_SOCKET);

    let command = SshCommandRunner::without_agent("/usr/bin/ssh-keygen")
        .command()
        .unwrap();
    let delta = env_delta(&command);

    assert_eq!(delta.get("SSH_AUTH_SOCK"), Some(&None));
}

/// The removal reaches the child process itself, not just the `Command` record.
#[test]
#[serial_test::serial]
fn test_output_without_agent_leaves_the_child_without_an_agent_socket() {
    let (_guard, _home) = guard_with_empty_home(&["HOME", "SSH_AUTH_SOCK"]);
    std::env::set_var("SSH_AUTH_SOCK", AGENT_SOCKET);

    let output = SshCommandRunner::without_agent(ENV_DUMP_PROGRAM)
        .output(no_args(), spawn_error)
        .unwrap();
    let dumped = String::from_utf8(output.stdout).unwrap();

    assert!(output.status.success());
    assert!(
        !dumped
            .lines()
            .any(|line| line.starts_with("SSH_AUTH_SOCK=")),
        "child kept an agent socket: {dumped}"
    );
}

/// The child keeps the rest of the parent environment. Only a real process can
/// show this, because clearing the environment leaves no trace on `Command`.
#[test]
#[serial_test::serial]
fn test_output_passes_the_parent_environment_to_the_child() {
    let (_guard, _home) = guard_with_empty_home(&[
        "HOME",
        "PATH",
        "SSH_AUTH_SOCK",
        "KAPSARO_PRIVATE_KEY",
        "CUSTOM_PARENT_ENV",
    ]);
    std::env::set_var("PATH", "/usr/bin");
    std::env::set_var("SSH_AUTH_SOCK", AGENT_SOCKET);
    std::env::set_var("KAPSARO_PRIVATE_KEY", "sensitive");
    std::env::set_var("CUSTOM_PARENT_ENV", "parent-value");

    let output = SshCommandRunner::optional_agent(
        ENV_DUMP_PROGRAM,
        Some(std::path::PathBuf::from(AGENT_SOCKET)),
    )
    .output(no_args(), spawn_error)
    .unwrap();

    let dumped = String::from_utf8(output.stdout).unwrap();
    let names: Vec<&str> = dumped
        .lines()
        .filter_map(|line| line.split('=').next())
        .collect();
    assert!(names.contains(&"PATH"));
    assert!(names.contains(&"CUSTOM_PARENT_ENV"));
    assert!(dumped.contains(&format!("SSH_AUTH_SOCK={}", AGENT_SOCKET)));
    assert!(!names.contains(&"KAPSARO_PRIVATE_KEY"));
}

/// Signing material travels on stdin so it never lands in a file.
#[test]
fn test_output_with_stdin_pipes_the_payload_to_the_child() {
    let output = SshCommandRunner::optional_agent(ECHO_STDIN_PROGRAM, None)
        .output_with_stdin(
            no_args(),
            b"stdin-signature-payload",
            spawn_error,
            "Failed to wait for test program",
        )
        .unwrap();

    assert_eq!(output.stdout, b"stdin-signature-payload");
}

/// A child that refuses the payload closes its end of the pipe, and the write
/// that fails is the first the runner hears of it. What the child wrote before
/// stopping is the only account of why, so the failure carries it.
#[test]
fn test_output_with_stdin_reports_what_the_child_wrote_before_refusing_the_payload() {
    let payload = vec![b'x'; 4 * 1024 * 1024];

    let error = SshCommandRunner::optional_agent(REFUSING_STDIN_PROGRAM, None)
        .output_with_stdin(
            ["-c", "echo refused-the-signing-payload >&2; exit 3"],
            &payload,
            spawn_error,
            "Failed to wait for test program",
        )
        .expect_err("a child that stops before reading stdin must fail the write");

    let message = error.format_user_message();
    assert!(message.contains("refused-the-signing-payload"), "{message}");
}

#[test]
#[serial_test::serial]
fn test_optional_agent_removes_an_ambient_socket_when_the_fixed_socket_is_absent() {
    let (_guard, _home) = guard_with_empty_home(&["HOME", "SSH_AUTH_SOCK"]);
    std::env::set_var("SSH_AUTH_SOCK", AGENT_SOCKET);

    let command = SshCommandRunner::optional_agent("/usr/bin/ssh-keygen", None)
        .command()
        .unwrap();

    assert_eq!(env_delta(&command).get("SSH_AUTH_SOCK"), Some(&None));
}

#[test]
#[serial_test::serial]
fn test_optional_agent_uses_the_fixed_socket_after_the_ambient_socket_changes() {
    let (_guard, _home) = guard_with_empty_home(&["HOME", "SSH_AUTH_SOCK"]);
    let fixed_socket = std::path::PathBuf::from("/tmp/kapsaro-fixed-agent.sock");
    std::env::set_var("SSH_AUTH_SOCK", "/tmp/kapsaro-replacement-agent.sock");

    let command = SshCommandRunner::optional_agent("/usr/bin/ssh-keygen", Some(fixed_socket))
        .command()
        .unwrap();

    assert_eq!(
        env_delta(&command)["SSH_AUTH_SOCK"],
        Some("/tmp/kapsaro-fixed-agent.sock".to_string())
    );
}

/// ssh-add cannot work without an agent, so the runner refuses before spawning.
#[test]
#[serial_test::serial]
fn test_required_agent_without_a_fixed_socket_error() {
    let (_guard, _home) = guard_with_empty_home(&["HOME", "SSH_AUTH_SOCK"]);
    std::env::remove_var("SSH_AUTH_SOCK");

    let error = SshCommandRunner::required_agent("/usr/bin/ssh-add", None)
        .command()
        .expect_err("a required agent socket must be resolved");

    assert_eq!(error.kind(), crate::ErrorKind::Ssh);
}
