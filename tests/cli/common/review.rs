// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

// Interactive helpers for the member-set review prompt in CLI integration tests.
// Wraps PTY-based command execution to accept or pass through the optional review prompt.

use super::execution::{
    run_command_with_optional_prompt_pty, run_command_with_optional_prompt_pty_after_input,
};
use std::path::Path;
#[cfg(unix)]
use std::process::Command as StdCommand;

use super::execution::kapsaro_std_cmd;

/// Runs a command that may show a member-set review prompt, confirms with "y", asserts success.
#[cfg(unix)]
pub fn assert_member_set_review_success(command: &mut StdCommand) -> String {
    let result = run_command_with_optional_prompt_pty(command, "member set", b"y\r");
    assert!(
        result.status.success(),
        "command failed while accepting or skipping member set review:\n{}",
        result.output
    );
    result.output
}

/// Like `assert_member_set_review_success` but feeds stdin content before the review prompt.
#[cfg(unix)]
pub fn assert_stdin_member_set_review_success(
    command: &mut StdCommand,
    stdin_content: &[u8],
) -> String {
    let mut input = stdin_content.to_vec();
    input.push(b'\n');
    input.push(0x04);
    let result =
        run_command_with_optional_prompt_pty_after_input(command, &input, "member set", b"y\r");
    assert!(
        result.status.success(),
        "command failed while accepting or skipping stdin member set review:\n{}",
        result.output
    );
    result.output
}

/// Runs `kapsaro set <key> <value>` with optional member handle and name, handling the review prompt.
#[cfg(unix)]
pub fn set_value_with_member_set_review(
    workspace: &Path,
    home: &Path,
    ssh_identity: &Path,
    key: &str,
    value: &str,
    member_handle: Option<&str>,
    name: Option<&str>,
) {
    let mut command = kapsaro_std_cmd();
    command
        .arg("set")
        .arg(key)
        .arg(value)
        .arg("--workspace")
        .arg(workspace)
        .env("KAPSARO_HOME", home)
        .env("KAPSARO_SSH_IDENTITY", ssh_identity);
    if let Some(member_handle) = member_handle {
        command.arg("--member-handle").arg(member_handle);
    }
    if let Some(name) = name {
        command.arg("--name").arg(name);
    }
    assert_member_set_review_success(&mut command);
}

/// Runs `kapsaro set <key> --stdin` with optional member handle and name, handling the review prompt.
#[cfg(unix)]
pub fn set_stdin_with_member_set_review(
    workspace: &Path,
    home: &Path,
    ssh_identity: &Path,
    key: &str,
    value: &[u8],
    member_handle: Option<&str>,
    name: Option<&str>,
) {
    let mut command = kapsaro_std_cmd();
    command
        .arg("set")
        .arg(key)
        .arg("--stdin")
        .arg("--workspace")
        .arg(workspace)
        .env("KAPSARO_HOME", home)
        .env("KAPSARO_SSH_IDENTITY", ssh_identity);
    if let Some(member_handle) = member_handle {
        command.arg("--member-handle").arg(member_handle);
    }
    if let Some(name) = name {
        command.arg("--name").arg(name);
    }
    assert_stdin_member_set_review_success(&mut command, value);
}

/// Runs `kapsaro encrypt <input> --out <output>` with member handle, handling the review prompt.
#[cfg(unix)]
pub fn encrypt_file_with_member_set_review(
    workspace: &Path,
    home: &Path,
    ssh_identity: &Path,
    input: &Path,
    output: &Path,
    member_handle: &str,
) -> String {
    let mut command = kapsaro_std_cmd();
    command
        .arg("encrypt")
        .arg(input)
        .arg("--out")
        .arg(output)
        .arg("--member-handle")
        .arg(member_handle)
        .arg("--workspace")
        .arg(workspace)
        .env("KAPSARO_HOME", home)
        .env("KAPSARO_SSH_IDENTITY", ssh_identity);
    assert_member_set_review_success(&mut command)
}

/// Runs `kapsaro encrypt --stdin` with member handle and optional output path, handling the review prompt.
#[cfg(unix)]
pub fn encrypt_stdin_with_member_set_review(
    workspace: &Path,
    home: &Path,
    ssh_identity: &Path,
    input: &[u8],
    output: Option<&Path>,
    stdout: bool,
    member_handle: &str,
) -> String {
    let mut command = kapsaro_std_cmd();
    command
        .arg("encrypt")
        .arg("--stdin")
        .arg("--member-handle")
        .arg(member_handle)
        .arg("--workspace")
        .arg(workspace)
        .env("KAPSARO_HOME", home)
        .env("KAPSARO_SSH_IDENTITY", ssh_identity);
    if let Some(output) = output {
        command.arg("--out").arg(output);
    }
    if stdout {
        command.arg("--stdout");
    }
    assert_stdin_member_set_review_success(&mut command, input)
}

/// Runs `kapsaro import <input>` with optional --json flag, handling the review prompt.
#[cfg(unix)]
pub fn import_file_with_member_set_review(
    workspace: &Path,
    home: &Path,
    ssh_identity: &Path,
    input: &Path,
    json: bool,
) -> String {
    let mut command = kapsaro_std_cmd();
    command
        .arg("import")
        .arg(input)
        .arg("--workspace")
        .arg(workspace)
        .env("KAPSARO_HOME", home)
        .env("KAPSARO_SSH_IDENTITY", ssh_identity);
    if json {
        command.arg("--json");
    }
    assert_member_set_review_success(&mut command)
}
