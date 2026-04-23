// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for io::ssh::external::pubkey module
//!
//! Tests for SSH public key retrieval utilities.

use secretenv::io::ssh::external::pubkey::{
    collect_ed25519_keys_in_output, load_ed25519_keys_from_agent, load_ssh_public_key_file,
    load_ssh_public_key_with_descriptor_trait, SshKeyCandidate,
};
use secretenv::io::ssh::external::traits::{SshAdd, SshKeygen};
use secretenv::io::ssh::protocol::key_descriptor::SshKeyDescriptor;
use secretenv::io::ssh::protocol::types::Ed25519RawSignature;
use secretenv::Result;
use std::path::PathBuf;
use tempfile::TempDir;

// Valid Ed25519 public key for testing
const VALID_ED25519_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA test@example.com";

const VALID_ED25519_KEY_NO_COMMENT: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

// A second distinct Ed25519 key (different base64 data)
const VALID_ED25519_KEY_2: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBb second@host";

const RSA_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ rsa-key@host";

// --- Mock SshAdd ---

struct MockSshAdd {
    output: Result<String>,
}

impl MockSshAdd {
    fn ok(output: &str) -> Self {
        Self {
            output: Ok(output.to_string()),
        }
    }

    fn err(message: &str) -> Self {
        Self {
            output: Err(secretenv::Error::from(
                secretenv::io::ssh::SshError::operation_failed(message),
            )),
        }
    }
}

impl SshAdd for MockSshAdd {
    fn list_keys(&self) -> Result<String> {
        match &self.output {
            Ok(s) => Ok(s.clone()),
            Err(e) => Err(secretenv::Error::from(
                secretenv::io::ssh::SshError::operation_failed(e.to_string()),
            )),
        }
    }
}

struct MockSshKeygen {
    derived_public_key: Result<String>,
}

impl MockSshKeygen {
    fn ok(public_key: &str) -> Self {
        Self {
            derived_public_key: Ok(public_key.to_string()),
        }
    }
}

impl SshKeygen for MockSshKeygen {
    fn derive_public_key(&self, _key_path: &std::path::Path) -> Result<String> {
        match &self.derived_public_key {
            Ok(value) => Ok(value.clone()),
            Err(error) => Err(secretenv::Error::from(
                secretenv::io::ssh::SshError::operation_failed(error.to_string()),
            )),
        }
    }

    fn sign(
        &self,
        _key_path: &std::path::Path,
        _namespace: &str,
        _data: &[u8],
    ) -> Result<Ed25519RawSignature> {
        unreachable!("sign is not used in this test");
    }

    fn verify(
        &self,
        _ssh_pubkey: &str,
        _namespace: &str,
        _message: &[u8],
        _signature: &str,
    ) -> Result<()> {
        unreachable!("verify is not used in this test");
    }
}

// --- Tests for existing functions (kept) ---

#[test]
fn test_load_ssh_public_key_file_valid_ed25519() {
    let temp_dir = TempDir::new().unwrap();
    let pub_path = temp_dir.path().join("test.pub");

    std::fs::write(&pub_path, format!("{}\n", VALID_ED25519_KEY)).unwrap();

    let result = load_ssh_public_key_file(&pub_path).unwrap();
    assert_eq!(result, VALID_ED25519_KEY);
}

#[test]
fn test_load_ssh_public_key_file_invalid_key_type() {
    let temp_dir = TempDir::new().unwrap();
    let pub_path = temp_dir.path().join("test.pub");

    std::fs::write(&pub_path, RSA_KEY).unwrap();

    let result = load_ssh_public_key_file(&pub_path);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Unsupported key type"));
}

#[test]
fn test_load_ssh_public_key_file_empty() {
    let temp_dir = TempDir::new().unwrap();
    let pub_path = temp_dir.path().join("test.pub");

    std::fs::write(&pub_path, "").unwrap();

    let result = load_ssh_public_key_file(&pub_path);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("empty or missing key type"));
}

#[test]
fn test_load_ssh_public_key_file_not_found() {
    let path = PathBuf::from("/nonexistent/test.pub");
    let result = load_ssh_public_key_file(&path);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Failed to read"));
}

#[cfg(unix)]
#[test]
fn test_load_ssh_public_key_file_rejects_symlink() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let real_path = temp_dir.path().join("real.pub");
    let link_path = temp_dir.path().join("test.pub");
    std::fs::write(&real_path, VALID_ED25519_KEY).unwrap();
    symlink(&real_path, &link_path).unwrap();

    let result = load_ssh_public_key_file(&link_path);
    assert!(result.is_err());
    let message = result.unwrap_err().to_string();
    assert!(message.contains("symlink"), "unexpected error: {message}");
}

#[test]
fn test_load_ssh_public_key_file_rejects_oversized_input() {
    let temp_dir = TempDir::new().unwrap();
    let pub_path = temp_dir.path().join("test.pub");
    let oversized = format!("{}{}\n", VALID_ED25519_KEY, "A".repeat(70 * 1024));
    std::fs::write(&pub_path, oversized).unwrap();

    let result = load_ssh_public_key_file(&pub_path);
    assert!(result.is_err());
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("maximum size limit"),
        "unexpected error: {message}"
    );
}

#[test]
fn test_load_ssh_public_key_with_descriptor_trait_public_key() {
    let temp_dir = TempDir::new().unwrap();
    let pub_path = temp_dir.path().join("test.pub");

    std::fs::write(&pub_path, format!("{}\n", VALID_ED25519_KEY)).unwrap();

    let descriptor = SshKeyDescriptor::from_path(pub_path);
    let ssh_keygen = MockSshKeygen::ok(VALID_ED25519_KEY_2);

    let result = load_ssh_public_key_with_descriptor_trait(&ssh_keygen, &descriptor).unwrap();
    assert_eq!(result, VALID_ED25519_KEY);
}

#[test]
fn test_load_ssh_public_key_with_descriptor_trait_private_key() {
    let descriptor = SshKeyDescriptor::from_path(PathBuf::from("/tmp/test_ed25519"));
    let ssh_keygen = MockSshKeygen::ok(VALID_ED25519_KEY);

    let result = load_ssh_public_key_with_descriptor_trait(&ssh_keygen, &descriptor).unwrap();

    assert_eq!(result, VALID_ED25519_KEY);
}

// --- Tests for collect_ed25519_keys_in_output ---

#[test]
fn test_collect_ed25519_keys_in_output_single_key() {
    let output = format!("{}\n", VALID_ED25519_KEY);
    let keys = collect_ed25519_keys_in_output(&output);
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], VALID_ED25519_KEY);
}

#[test]
fn test_collect_ed25519_keys_in_output_multiple_mixed() {
    let output = format!(
        "{}\n{}\n{}\n",
        RSA_KEY, VALID_ED25519_KEY, VALID_ED25519_KEY_2
    );
    let keys = collect_ed25519_keys_in_output(&output);
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], VALID_ED25519_KEY);
    assert_eq!(keys[1], VALID_ED25519_KEY_2);
}

#[test]
fn test_collect_ed25519_keys_in_output_no_ed25519() {
    let output = format!("{}\n", RSA_KEY);
    let keys = collect_ed25519_keys_in_output(&output);
    assert!(keys.is_empty());
}

#[test]
fn test_collect_ed25519_keys_in_output_empty() {
    let keys = collect_ed25519_keys_in_output("");
    assert!(keys.is_empty());
}

// --- Tests for load_ed25519_keys_from_agent ---

#[test]
fn test_load_ed25519_keys_from_agent_single_key() {
    let mock = MockSshAdd::ok(VALID_ED25519_KEY);
    let candidates = load_ed25519_keys_from_agent(&mock).unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].public_key, VALID_ED25519_KEY);
    assert_eq!(candidates[0].comment, "test@example.com");
    assert!(candidates[0].fingerprint.starts_with("SHA256:"));
}

#[test]
fn test_load_ed25519_keys_from_agent_multiple_mixed() {
    let output = format!(
        "{}\n{}\n{}\n",
        RSA_KEY, VALID_ED25519_KEY, VALID_ED25519_KEY_2
    );
    let mock = MockSshAdd::ok(&output);
    let candidates = load_ed25519_keys_from_agent(&mock).unwrap();
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].comment, "test@example.com");
    assert_eq!(candidates[1].comment, "second@host");
}

#[test]
fn test_load_ed25519_keys_from_agent_no_ed25519() {
    let mock = MockSshAdd::ok(RSA_KEY);
    let candidates = load_ed25519_keys_from_agent(&mock).unwrap();
    assert!(candidates.is_empty());
}

#[test]
fn test_load_ed25519_keys_from_agent_empty_output() {
    let mock = MockSshAdd::ok("");
    let candidates = load_ed25519_keys_from_agent(&mock).unwrap();
    assert!(candidates.is_empty());
}

#[test]
fn test_load_ed25519_keys_from_agent_empty_comment() {
    let mock = MockSshAdd::ok(VALID_ED25519_KEY_NO_COMMENT);
    let candidates = load_ed25519_keys_from_agent(&mock).unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].comment, "");
    assert!(candidates[0].fingerprint.starts_with("SHA256:"));
}

#[test]
fn test_load_ed25519_keys_from_agent_error() {
    let mock = MockSshAdd::err("agent not running");
    let result = load_ed25519_keys_from_agent(&mock);
    assert!(result.is_err());
}

// --- Tests for SshKeyCandidate ---

#[test]
fn test_ssh_key_candidate_fields() {
    let candidate = SshKeyCandidate {
        public_key: VALID_ED25519_KEY.to_string(),
        fingerprint: "SHA256:abc123".to_string(),
        comment: "test@example.com".to_string(),
    };
    assert_eq!(candidate.public_key, VALID_ED25519_KEY);
    assert_eq!(candidate.fingerprint, "SHA256:abc123");
    assert_eq!(candidate.comment, "test@example.com");
}
