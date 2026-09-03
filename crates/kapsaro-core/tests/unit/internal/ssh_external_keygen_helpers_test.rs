// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for private helpers in io/ssh/external/keygen.rs.
//!
//! These tests synthesize `std::process::Output` values directly so the
//! helpers can be exercised without invoking the real `ssh-keygen` binary.
//! Executable stubs are serialized because they inspect process-wide SSH_AUTH_SOCK.

use super::{
    build_derive_public_key_args, build_sign_args, check_sign_output, execute_sign_command,
    parse_sign_stdout,
};
use crate::format::codec::codec_base64_fixtures::encode_base64_standard;
use crate::io::ssh::protocol::constants::KEY_PROTECTION_NAMESPACE;
use crate::io::ssh::protocol::parse::decode_ssh_public_key_blob;
use crate::io::ssh::protocol::wire::encode_ssh_string;
use crate::test_utils::process_output::{
    build_process_output, failed_code, save_agent_socket_echo_script,
};

const TEST_SSH_PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com";
const OTHER_SSH_PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkB6jid+Y/7wt0S+9jTJGX1UytxIHOO3GXVPZPY1OYT other@example.com";

fn append_publickey(blob: &mut Vec<u8>, ssh_pubkey: &str) {
    let publickey = decode_ssh_public_key_blob(ssh_pubkey).unwrap();
    blob.extend_from_slice(&encode_ssh_string(&publickey).unwrap());
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

    assert_eq!(err.kind(), crate::ErrorKind::Ssh);
    let message = err.format_user_message();
    assert!(message.contains("ssh-keygen -Y sign failed"));
    assert!(message.contains("permission denied"));
    // Signing from a private key file runs without the agent, so the hint names
    // the file itself, its passphrase, and the .pub file that reaches the agent.
    assert!(message.contains("Check that the private key file is readable"));
    assert!(message.contains("passphrase"));
    assert!(message.contains("pass the matching .pub file to sign through ssh-agent"));
}

#[test]
fn test_check_sign_output_failure_public_key_hint() {
    let output = build_process_output(failed_code(), b"public key not loaded\n", b"");
    let err = check_sign_output(&output, true).expect_err("non-zero exit must fail");

    assert_eq!(err.kind(), crate::ErrorKind::Ssh);
    let message = err.format_user_message();
    assert!(message.contains("ssh-add -l"));
    assert!(message.contains("corresponding private key must be loaded in ssh-agent"));
    // Public-key hint is mutually exclusive with the private-key hint.
    assert!(!message.contains("Check that the private key file is readable"));
}

#[test]
fn test_check_sign_output_failure_non_utf8_stderr_uses_lossy_decode() {
    // 0xFF is invalid UTF-8 and must be replaced by the Unicode replacement char
    // via String::from_utf8_lossy, not cause a panic.
    let output = build_process_output(failed_code(), &[0xFFu8, b' ', b'o', b'k'], b"");
    let err = check_sign_output(&output, false).expect_err("non-zero exit must fail");
    assert_eq!(err.kind(), crate::ErrorKind::Ssh);
    let msg = err.format_user_message();
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
    sshsig_blob.extend_from_slice(&encode_ssh_string(KEY_PROTECTION_NAMESPACE.as_bytes()).unwrap());
    sshsig_blob.extend_from_slice(&encode_ssh_string(b"").unwrap());
    sshsig_blob.extend_from_slice(&encode_ssh_string(b"sha256").unwrap());

    let mut signature_blob = Vec::new();
    signature_blob.extend_from_slice(&encode_ssh_string(b"ssh-ed25519").unwrap());
    signature_blob.extend_from_slice(&encode_ssh_string(&raw_sig).unwrap());
    sshsig_blob.extend_from_slice(&encode_ssh_string(&signature_blob).unwrap());

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
    sshsig_blob.extend_from_slice(&encode_ssh_string(KEY_PROTECTION_NAMESPACE.as_bytes()).unwrap());
    sshsig_blob.extend_from_slice(&encode_ssh_string(b"").unwrap());
    sshsig_blob.extend_from_slice(&encode_ssh_string(b"sha256").unwrap());

    let mut signature_blob = Vec::new();
    signature_blob.extend_from_slice(&encode_ssh_string(b"ssh-ed25519").unwrap());
    signature_blob.extend_from_slice(&encode_ssh_string(&raw_sig).unwrap());
    sshsig_blob.extend_from_slice(&encode_ssh_string(&signature_blob).unwrap());

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
// argument builders
// --------------------------------------------------------------------

#[test]
fn test_build_derive_public_key_args_passes_the_key_path_to_the_f_flag() {
    let args = build_derive_public_key_args(std::path::Path::new("/tmp/id_ed25519"));

    assert_eq!(args, vec!["-y", "-f", "/tmp/id_ed25519"]);
}

/// Omitting `-O hashalg=sha256` makes ssh-keygen pick its own default, and the
/// SSHSIG parser only accepts sha256.
#[test]
fn test_build_sign_args_requests_sha256_and_binds_the_namespace() {
    let args = build_sign_args("/tmp/id_ed25519", KEY_PROTECTION_NAMESPACE);

    assert_eq!(
        args,
        [
            "-Y",
            "sign",
            "-f",
            "/tmp/id_ed25519",
            "-n",
            KEY_PROTECTION_NAMESPACE,
            "-O",
            "hashalg=sha256",
        ]
    );
}

/// No output path is passed, so ssh-keygen writes the signature to stdout and
/// never leaves signature material on disk.
#[test]
fn test_build_sign_args_names_no_output_file() {
    let args = build_sign_args("/tmp/id_ed25519", KEY_PROTECTION_NAMESPACE);

    assert_eq!(args.len(), 8);
}

#[cfg(target_family = "unix")]
#[test]
#[serial_test::serial]
fn test_public_key_signing_uses_the_fixed_socket_after_the_environment_changes() {
    let _guard = crate::test_utils::EnvGuard::new(&["SSH_AUTH_SOCK"]);
    let temp = tempfile::TempDir::new().unwrap();
    let script = save_agent_socket_echo_script(temp.path(), "ssh-keygen-stub");
    let fixed_socket = temp.path().join("fixed.sock");
    std::env::set_var("SSH_AUTH_SOCK", temp.path().join("replacement.sock"));

    let output = execute_sign_command(
        &script.to_string_lossy(),
        "/tmp/test.pub",
        KEY_PROTECTION_NAMESPACE,
        b"message",
        true,
        Some(fixed_socket.clone()),
    )
    .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.trim(), fixed_socket.to_str().unwrap());
}

#[cfg(target_family = "unix")]
#[test]
#[serial_test::serial]
fn test_public_key_signing_removes_ambient_socket_when_the_fixed_socket_is_absent() {
    let _guard = crate::test_utils::EnvGuard::new(&["SSH_AUTH_SOCK"]);
    let temp = tempfile::TempDir::new().unwrap();
    let script = save_agent_socket_echo_script(temp.path(), "ssh-keygen-stub");
    std::env::set_var("SSH_AUTH_SOCK", temp.path().join("ambient.sock"));

    let output = execute_sign_command(
        &script.to_string_lossy(),
        "/tmp/test.pub",
        KEY_PROTECTION_NAMESPACE,
        b"message",
        true,
        None,
    )
    .unwrap();

    assert!(String::from_utf8(output.stdout).unwrap().trim().is_empty());
}
