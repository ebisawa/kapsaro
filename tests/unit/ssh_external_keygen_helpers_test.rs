// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for private helpers in io/ssh/external/keygen.rs.
//!
//! These tests synthesize `std::process::Output` values directly so the
//! helpers can be exercised without invoking the real `ssh-keygen` binary.

#![cfg(any(unix, windows))]

use super::{check_sign_output, check_verify_output};
use crate::Error;

#[cfg(unix)]
fn make_output(code: i32, stderr: &[u8], stdout: &[u8]) -> std::process::Output {
    use std::os::unix::process::ExitStatusExt;
    std::process::Output {
        status: std::process::ExitStatus::from_raw(code),
        stderr: stderr.to_vec(),
        stdout: stdout.to_vec(),
    }
}

#[cfg(windows)]
fn make_output(code: u32, stderr: &[u8], stdout: &[u8]) -> std::process::Output {
    use std::os::windows::process::ExitStatusExt;
    std::process::Output {
        status: std::process::ExitStatus::from_raw(code),
        stderr: stderr.to_vec(),
        stdout: stdout.to_vec(),
    }
}

/// Helper that converts the platform-specific "exit code 1" raw value.
#[cfg(unix)]
fn failed_code() -> i32 {
    // Unix raw wait status: exit code 1 is encoded as 1 << 8 = 256.
    256
}

#[cfg(windows)]
fn failed_code() -> u32 {
    1
}

// --------------------------------------------------------------------
// check_sign_output
// --------------------------------------------------------------------

#[test]
fn test_check_sign_output_success_returns_ok() {
    let output = make_output(0, b"", b"");
    assert!(check_sign_output(&output, false).is_ok());
}

#[test]
fn test_check_sign_output_success_ignores_is_public_key_flag() {
    let output = make_output(0, b"", b"");
    assert!(check_sign_output(&output, true).is_ok());
}

#[test]
fn test_check_sign_output_failure_private_key_hint() {
    let output = make_output(failed_code(), b"permission denied\n", b"");
    let err = check_sign_output(&output, false).expect_err("non-zero exit must fail");

    match err {
        Error::Ssh { message, .. } => {
            assert!(message.contains("ssh-keygen -Y sign failed"));
            assert!(message.contains("permission denied"));
            assert!(message.contains("Ensure the private key file is accessible"));
        }
        other => panic!("expected Error::Ssh, got {:?}", other),
    }
}

#[test]
fn test_check_sign_output_failure_public_key_hint() {
    let output = make_output(failed_code(), b"public key not loaded\n", b"");
    let err = check_sign_output(&output, true).expect_err("non-zero exit must fail");

    match err {
        Error::Ssh { message, .. } => {
            assert!(message.contains("ssh-add -l"));
            assert!(message.contains("corresponding private key must be loaded in ssh-agent"));
            // Public-key hint is mutually exclusive with the private-key hint.
            assert!(!message.contains("Ensure the private key file is accessible"));
        }
        other => panic!("expected Error::Ssh, got {:?}", other),
    }
}

#[test]
fn test_check_sign_output_failure_non_utf8_stderr_uses_lossy_decode() {
    // 0xFF is invalid UTF-8 and must be replaced by the Unicode replacement char
    // via String::from_utf8_lossy, not cause a panic.
    let output = make_output(failed_code(), &[0xFFu8, b' ', b'o', b'k'], b"");
    let err = check_sign_output(&output, false).expect_err("non-zero exit must fail");
    let msg = match err {
        Error::Ssh { message, .. } => message,
        other => panic!("expected Error::Ssh, got {:?}", other),
    };
    assert!(msg.contains("ssh-keygen -Y sign failed"));
    // Replacement char or the trailing ASCII chars should survive in the message.
    assert!(msg.contains("ok") || msg.contains('\u{FFFD}'));
}

// --------------------------------------------------------------------
// check_verify_output
// --------------------------------------------------------------------

#[test]
fn test_check_verify_output_success_returns_ok() {
    let output = make_output(0, b"", b"");
    assert!(check_verify_output(output).is_ok());
}

#[test]
fn test_check_verify_output_failure_with_stderr_uses_stderr() {
    let output = make_output(failed_code(), b"signature verification failed\n", b"");
    let err = check_verify_output(output).expect_err("non-zero exit must fail");

    match err {
        Error::Ssh { message, .. } => {
            assert!(message.contains("ssh-keygen -Y verify failed"));
            assert!(message.contains("signature verification failed"));
        }
        other => panic!("expected Error::Ssh, got {:?}", other),
    }
}

#[test]
fn test_check_verify_output_failure_stdout_only_falls_back_to_stdout() {
    let output = make_output(failed_code(), b"", b"stdout diagnostic message");
    let err = check_verify_output(output).expect_err("non-zero exit must fail");

    match err {
        Error::Ssh { message, .. } => {
            assert!(message.contains("stdout diagnostic message"));
        }
        other => panic!("expected Error::Ssh, got {:?}", other),
    }
}

#[test]
fn test_check_verify_output_failure_both_empty_uses_exit_code() {
    let output = make_output(failed_code(), b"", b"");
    let err = check_verify_output(output).expect_err("non-zero exit must fail");

    match err {
        Error::Ssh { message, .. } => {
            assert!(message.contains("ssh-keygen -Y verify failed"));
            assert!(message.contains("exit code:"));
        }
        other => panic!("expected Error::Ssh, got {:?}", other),
    }
}

#[test]
fn test_check_verify_output_failure_trims_trailing_whitespace() {
    let output = make_output(failed_code(), b"   bad signature   \n\n", b"");
    let err = check_verify_output(output).expect_err("non-zero exit must fail");

    match err {
        Error::Ssh { message, .. } => {
            // Trailing newlines / spaces removed by `.trim()`.
            assert!(message.ends_with("bad signature"));
        }
        other => panic!("expected Error::Ssh, got {:?}", other),
    }
}

#[test]
fn test_check_verify_output_failure_prefers_stderr_over_stdout() {
    let output = make_output(failed_code(), b"from stderr", b"from stdout");
    let err = check_verify_output(output).expect_err("non-zero exit must fail");

    match err {
        Error::Ssh { message, .. } => {
            assert!(message.contains("from stderr"));
            assert!(!message.contains("from stdout"));
        }
        other => panic!("expected Error::Ssh, got {:?}", other),
    }
}
