// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the ssh-add adapter.
//! Covers agent listing output handling and the required agent socket.
//! Executable stubs are serialized because they inspect process-wide SSH_AUTH_SOCK.

use super::{parse_list_keys_output, DefaultSshAdd};
use crate::io::ssh::external::traits::SshAdd;
use crate::test_utils::process_output::{
    build_process_output, failed_code, save_agent_socket_echo_script,
};

#[test]
fn test_parse_list_keys_output_returns_the_agent_listing() {
    let output = build_process_output(0, b"", b"ssh-ed25519 AAAA alice@example.com\n");

    let listing = parse_list_keys_output(output).unwrap();

    assert_eq!(listing, "ssh-ed25519 AAAA alice@example.com\n");
}

/// The agent's own diagnostic is the only clue about why listing failed, so it
/// has to survive into the reported error.
#[test]
fn test_parse_list_keys_output_reports_a_nonzero_exit_with_stderr() {
    let output = build_process_output(failed_code(), b"Could not open a connection\n", b"");

    let error = parse_list_keys_output(output).expect_err("a non-zero exit must fail");

    assert_eq!(error.kind(), crate::ErrorKind::Ssh);
    let message = error.format_user_message();
    assert!(message.contains("ssh-add -L failed"), "{message}");
    assert!(message.contains("Could not open a connection"), "{message}");
}

#[test]
fn test_parse_list_keys_output_reports_invalid_utf8() {
    let output = build_process_output(0, b"", &[0xFF]);

    let error = parse_list_keys_output(output).expect_err("invalid UTF-8 must fail");

    assert_eq!(error.kind(), crate::ErrorKind::Ssh);
    assert!(error
        .format_user_message()
        .contains("Invalid UTF-8 in ssh-add output"));
}

/// Listing keys is meaningless without an agent, so resolution failure stops
/// the call before a process is started.
#[test]
fn test_list_keys_without_fixed_agent_socket_error() {
    let error = DefaultSshAdd::new("/should/not/run", None)
        .list_keys()
        .expect_err("an absent fixed agent socket must fail");

    assert_eq!(error.kind(), crate::ErrorKind::Ssh);
}

#[cfg(target_family = "unix")]
#[test]
#[serial_test::serial]
fn test_list_keys_uses_the_fixed_socket_after_the_environment_changes() {
    let _guard = crate::test_utils::EnvGuard::new(&["SSH_AUTH_SOCK"]);
    let temp = tempfile::TempDir::new().unwrap();
    let script = save_agent_socket_echo_script(temp.path(), "ssh-add-stub");
    let fixed_socket = temp.path().join("fixed.sock");
    let ssh_add = DefaultSshAdd::new(script.to_string_lossy(), Some(fixed_socket.clone()));
    std::env::set_var("SSH_AUTH_SOCK", temp.path().join("replacement.sock"));

    let output = ssh_add.list_keys().unwrap();

    assert_eq!(output.trim(), fixed_socket.to_str().unwrap());
}
