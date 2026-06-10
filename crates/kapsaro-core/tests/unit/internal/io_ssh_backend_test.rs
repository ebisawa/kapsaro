// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for Signature Backend abstraction (Phase 12.1 - TDD Red phase)

use crate::io::ssh::agent::client::DefaultAgentSigner;
use crate::io::ssh::backend::ssh_agent::SshAgentBackend;
use crate::io::ssh::backend::ssh_keygen::SshKeygenBackend;
use crate::io::ssh::backend::SignatureBackend;
use crate::io::ssh::external::keygen::DefaultSshKeygen;
use crate::io::ssh::protocol::constants::KEY_PROTECTION_NAMESPACE;
use crate::io::ssh::protocol::key_descriptor::SshKeyDescriptor;
use crate::io::ssh::protocol::types::Ed25519RawSignature;
use crate::test_utils::stub_agent_signer;

#[test]
fn test_backend_trait_determinism_check() {
    // Mock backend for testing
    struct DeterministicBackend;
    impl SignatureBackend for DeterministicBackend {
        fn sign_sshsig(
            &self,
            _namespace: &str,
            _pubkey: &str,
            _challenge: &[u8],
        ) -> kapsaro_core::Result<Ed25519RawSignature> {
            let mut bytes = [0u8; 64];
            bytes[0] = 1;
            bytes[1] = 2;
            bytes[2] = 3;
            bytes[3] = 4;
            Ok(Ed25519RawSignature::new(bytes)) // Always same
        }
    }

    let backend = DeterministicBackend;
    let result = backend.check_sshsig_determinism(KEY_PROTECTION_NAMESPACE, "fake-key", b"test");
    assert!(result.is_ok());
    let signature = backend
        .sign_sshsig_deterministic(KEY_PROTECTION_NAMESPACE, "fake-key", b"test")
        .expect("deterministic signing should succeed");
    assert_eq!(signature.as_bytes()[0], 1);
}

#[test]
fn test_backend_trait_non_deterministic_error() {
    use std::cell::Cell;

    struct NonDeterministicBackend {
        counter: Cell<u8>,
    }
    impl SignatureBackend for NonDeterministicBackend {
        fn sign_sshsig(
            &self,
            _namespace: &str,
            _pubkey: &str,
            _challenge: &[u8],
        ) -> kapsaro_core::Result<Ed25519RawSignature> {
            let val = self.counter.get();
            self.counter.set(val + 1);
            let mut bytes = [0u8; 64];
            bytes[0] = val;
            Ok(Ed25519RawSignature::new(bytes)) // Different each time
        }
    }

    let backend = NonDeterministicBackend {
        counter: Cell::new(0),
    };
    let result = backend.check_sshsig_determinism(KEY_PROTECTION_NAMESPACE, "fake-key", b"test");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("deterministic") || err_msg.contains("Non-deterministic"),
        "Error message should mention determinism: {}",
        err_msg
    );
    let signature_result =
        backend.sign_sshsig_deterministic(KEY_PROTECTION_NAMESPACE, "fake-key", b"test");
    assert!(signature_result.is_err());
}

#[test]
#[ignore = "Requires ssh-agent with loaded key"]
fn test_ssh_agent_backend_real() {
    let backend = SshAgentBackend::new(stub_agent_signer());

    // This test requires:
    // 1. SSH_AUTH_SOCK environment variable set
    // 2. A key loaded in ssh-agent
    // 3. The public key string of that loaded key

    // Get first loaded key from ssh-agent (if available)
    use std::process::Command;
    let output = Command::new("ssh-add")
        .arg("-L")
        .output()
        .expect("Failed to run ssh-add -L");

    if !output.status.success() {
        eprintln!("ssh-add -L failed, skipping test");
        return;
    }

    let keys_output = String::from_utf8_lossy(&output.stdout);
    let first_line = keys_output.lines().next();
    if first_line.is_none() {
        eprintln!("No keys loaded in ssh-agent, skipping test");
        return;
    }

    let pubkey = first_line.unwrap();
    let challenge = b"test challenge for ssh-agent backend";

    let result = backend.sign_sshsig(KEY_PROTECTION_NAMESPACE, pubkey, challenge);
    assert!(
        result.is_ok(),
        "ssh-agent backend should succeed with loaded key: {:?}",
        result.err()
    );

    let signature = result.unwrap();
    assert_eq!(
        signature.as_bytes().len(),
        64,
        "Signature should be 64 bytes"
    );
}

#[test]
#[ignore = "Requires ssh-keygen command"]
fn test_ssh_keygen_backend_real() {
    // Use a realistic SSH key path for testing
    let ssh_key_path = std::path::PathBuf::from(
        std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string()) + "/.ssh/id_ed25519",
    );
    let backend = SshKeygenBackend::new(
        Box::new(DefaultSshKeygen::new("ssh-keygen")),
        SshKeyDescriptor::from_path(ssh_key_path),
    );

    // This test requires:
    // 1. ssh-keygen command available
    // 2. ssh-keygen supports -Y sign (OpenSSH 8.0+)
    // 3. A key loaded in ssh-agent (for signing)

    // Check if ssh-keygen supports -Y sign
    use std::process::Command;
    let check = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-h"])
        .output();

    if check.is_err() {
        eprintln!("ssh-keygen not available, skipping test");
        return;
    }

    // Get first loaded key
    let output = Command::new("ssh-add")
        .arg("-L")
        .output()
        .expect("Failed to run ssh-add -L");

    if !output.status.success() {
        eprintln!("ssh-add -L failed, skipping test");
        return;
    }

    let keys_output = String::from_utf8_lossy(&output.stdout);
    let first_line = keys_output.lines().next();
    if first_line.is_none() {
        eprintln!("No keys loaded in ssh-agent, skipping test");
        return;
    }

    let pubkey = first_line.unwrap();
    let challenge = b"test challenge for ssh-keygen backend";

    let result = backend.sign_sshsig(KEY_PROTECTION_NAMESPACE, pubkey, challenge);
    assert!(
        result.is_ok(),
        "ssh-keygen backend should succeed: {:?}",
        result.err()
    );

    let signature = result.unwrap();
    assert_eq!(
        signature.as_bytes().len(),
        64,
        "Signature should be 64 bytes"
    );
}

#[test]
fn test_ssh_keygen_backend_command_not_found() {
    let backend = SshKeygenBackend::new(
        Box::new(DefaultSshKeygen::new("/nonexistent/ssh-keygen")),
        SshKeyDescriptor::from_path(std::path::PathBuf::from("/dummy/key")),
    );
    let result = backend.sign_sshsig(KEY_PROTECTION_NAMESPACE, "fake-key", b"test");

    assert!(result.is_err(), "Should fail with nonexistent command");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("ssh-keygen") || err_msg.contains("command") || err_msg.contains("failed"),
        "Error should mention ssh-keygen command failure: {}",
        err_msg
    );
}

#[test]
fn test_ssh_agent_backend_no_auth_sock() {
    // Save original SSH_AUTH_SOCK
    let original = std::env::var("SSH_AUTH_SOCK").ok();

    // Remove SSH_AUTH_SOCK
    std::env::remove_var("SSH_AUTH_SOCK");

    let backend = SshAgentBackend::new(Box::new(DefaultAgentSigner));
    let result = backend.sign_sshsig(KEY_PROTECTION_NAMESPACE, "fake-key", b"test");

    // Restore SSH_AUTH_SOCK
    if let Some(val) = original {
        std::env::set_var("SSH_AUTH_SOCK", val);
    }

    assert!(result.is_err(), "Should fail without SSH_AUTH_SOCK");
}
