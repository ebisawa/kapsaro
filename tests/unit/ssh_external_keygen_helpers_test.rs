// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for private helpers in io/ssh/external/keygen.rs.
//!
//! These tests synthesize `std::process::Output` values directly so the
//! helpers can be exercised without invoking the real `ssh-keygen` binary.

#![cfg(any(unix, windows))]

use super::{check_sign_output, check_verify_output, parse_sign_stdout};
use crate::io::ssh::protocol::constants::KEY_PROTECTION_NAMESPACE;
use crate::io::ssh::protocol::parse::decode_ssh_public_key_blob;
use crate::io::ssh::protocol::wire::encode_ssh_string;
use crate::support::codec::base64_public::encode_base64_standard;
use crate::Error;

const TEST_SSH_PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com";
const OTHER_SSH_PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkB6jid+Y/7wt0S+9jTJGX1UytxIHOO3GXVPZPY1OYT other@example.com";

fn append_publickey(blob: &mut Vec<u8>, ssh_pubkey: &str) {
    let publickey = decode_ssh_public_key_blob(ssh_pubkey).unwrap();
    blob.extend_from_slice(&encode_ssh_string(&publickey));
}

#[cfg(unix)]
fn build_process_output(code: i32, stderr: &[u8], stdout: &[u8]) -> std::process::Output {
    use std::os::unix::process::ExitStatusExt;
    std::process::Output {
        status: std::process::ExitStatus::from_raw(code),
        stderr: stderr.to_vec(),
        stdout: stdout.to_vec(),
    }
}

#[cfg(windows)]
fn build_process_output(code: u32, stderr: &[u8], stdout: &[u8]) -> std::process::Output {
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
fn test_check_sign_output_accepts_zero_exit() {
    let output = build_process_output(0, b"", b"");
    assert!(check_sign_output(&output, false).is_ok());
}

#[test]
fn test_check_sign_output_ignores_public_key_flag_on_zero_exit() {
    let output = build_process_output(0, b"", b"");
    assert!(check_sign_output(&output, true).is_ok());
}

#[test]
fn test_check_sign_output_failure_private_key_hint() {
    let output = build_process_output(failed_code(), b"permission denied\n", b"");
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
    let output = build_process_output(failed_code(), b"public key not loaded\n", b"");
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
    let output = build_process_output(failed_code(), &[0xFFu8, b' ', b'o', b'k'], b"");
    let err = check_sign_output(&output, false).expect_err("non-zero exit must fail");
    let msg = match err {
        Error::Ssh { message, .. } => message,
        other => panic!("expected Error::Ssh, got {:?}", other),
    };
    assert!(msg.contains("ssh-keygen -Y sign failed"));
    // Replacement char or the trailing ASCII chars should survive in the message.
    assert!(msg.contains("ok") || msg.contains('\u{FFFD}'));
}

#[test]
fn test_parse_sign_stdout_extracts_ed25519_signature() {
    let mut raw_sig = [0u8; 64];
    for (index, byte) in raw_sig.iter_mut().enumerate() {
        *byte = index as u8;
    }

    let mut sshsig_blob = Vec::new();
    sshsig_blob.extend_from_slice(b"SSHSIG");
    sshsig_blob.extend_from_slice(&1u32.to_be_bytes());
    append_publickey(&mut sshsig_blob, TEST_SSH_PUBKEY);
    sshsig_blob.extend_from_slice(&encode_ssh_string(KEY_PROTECTION_NAMESPACE.as_bytes()));
    sshsig_blob.extend_from_slice(&encode_ssh_string(b""));
    sshsig_blob.extend_from_slice(&encode_ssh_string(b"sha256"));

    let mut signature_blob = Vec::new();
    signature_blob.extend_from_slice(&encode_ssh_string(b"ssh-ed25519"));
    signature_blob.extend_from_slice(&encode_ssh_string(&raw_sig));
    sshsig_blob.extend_from_slice(&encode_ssh_string(&signature_blob));

    let armored = format!(
        "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
        encode_base64_standard(&sshsig_blob)
    );

    let signature = parse_sign_stdout(
        armored.into_bytes(),
        KEY_PROTECTION_NAMESPACE,
        TEST_SSH_PUBKEY,
    )
    .unwrap();
    assert_eq!(signature.as_bytes(), &raw_sig);
}

#[test]
fn test_parse_sign_stdout_rejects_publickey_mismatch() {
    let raw_sig = [0xAAu8; 64];
    let mut sshsig_blob = Vec::new();
    sshsig_blob.extend_from_slice(b"SSHSIG");
    sshsig_blob.extend_from_slice(&1u32.to_be_bytes());
    append_publickey(&mut sshsig_blob, OTHER_SSH_PUBKEY);
    sshsig_blob.extend_from_slice(&encode_ssh_string(KEY_PROTECTION_NAMESPACE.as_bytes()));
    sshsig_blob.extend_from_slice(&encode_ssh_string(b""));
    sshsig_blob.extend_from_slice(&encode_ssh_string(b"sha256"));

    let mut signature_blob = Vec::new();
    signature_blob.extend_from_slice(&encode_ssh_string(b"ssh-ed25519"));
    signature_blob.extend_from_slice(&encode_ssh_string(&raw_sig));
    sshsig_blob.extend_from_slice(&encode_ssh_string(&signature_blob));

    let armored = format!(
        "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
        encode_base64_standard(&sshsig_blob)
    );

    let err = parse_sign_stdout(
        armored.into_bytes(),
        KEY_PROTECTION_NAMESPACE,
        TEST_SSH_PUBKEY,
    )
    .unwrap_err();
    assert!(err.to_string().contains("publickey"));
}

#[test]
fn test_parse_sign_stdout_rejects_empty_output() {
    let err = parse_sign_stdout(Vec::new(), KEY_PROTECTION_NAMESPACE, TEST_SSH_PUBKEY).unwrap_err();
    assert!(err
        .to_string()
        .contains("ssh-keygen -Y sign produced empty signature output"));
}

#[test]
fn test_parse_sign_stdout_rejects_invalid_utf8() {
    let err = parse_sign_stdout(vec![0xFF], KEY_PROTECTION_NAMESPACE, TEST_SSH_PUBKEY).unwrap_err();
    assert!(err
        .to_string()
        .contains("Invalid UTF-8 in ssh-keygen output"));
}

// --------------------------------------------------------------------
// check_verify_output
// --------------------------------------------------------------------

#[test]
fn test_check_verify_output_accepts_zero_exit() {
    let output = build_process_output(0, b"", b"");
    assert!(check_verify_output(output).is_ok());
}

#[test]
fn test_check_verify_output_failure_with_stderr_uses_stderr() {
    let output = build_process_output(failed_code(), b"signature verification failed\n", b"");
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
    let output = build_process_output(failed_code(), b"", b"stdout diagnostic message");
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
    let output = build_process_output(failed_code(), b"", b"");
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
    let output = build_process_output(failed_code(), b"   bad signature   \n\n", b"");
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
    let output = build_process_output(failed_code(), b"from stderr", b"from stdout");
    let err = check_verify_output(output).expect_err("non-zero exit must fail");

    match err {
        Error::Ssh { message, .. } => {
            assert!(message.contains("from stderr"));
            assert!(!message.contains("from stdout"));
        }
        other => panic!("expected Error::Ssh, got {:?}", other),
    }
}
