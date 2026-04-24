// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH public key retrieval utilities

use crate::io::ssh::external::traits::{SshAdd, SshKeygen};
use crate::io::ssh::protocol::constants as ssh;
use crate::io::ssh::protocol::fingerprint::build_sha256_fingerprint;
use crate::io::ssh::protocol::key_descriptor::SshKeyDescriptor;
use crate::io::ssh::SshError;
use crate::support::fs::load_text_with_limit;
use crate::support::limits::MAX_SSH_PUBLIC_KEY_FILE_SIZE;
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::path::Path;

/// Candidate SSH key discovered from the agent or a file.
#[derive(Debug)]
pub struct SshKeyCandidate {
    /// Full public key line: "ssh-ed25519 AAAA... comment"
    pub public_key: String,
    /// SHA256 fingerprint: "SHA256:abc123..."
    pub fingerprint: String,
    /// Trailing comment extracted from the key line (may be empty)
    pub comment: String,
}

/// Create an SSH error (convenience for replacing `utils::error::ssh_error`).
fn ssh_error(message: impl Into<String>) -> Error {
    SshError::build_operation_failed_error(message).into()
}

/// Read SSH public key directly from a .pub file
///
/// This function reads an OpenSSH-format public key from a .pub file
/// and validates that it's an Ed25519 key.
///
/// # Arguments
///
/// * `pub_key_path` - Path to the .pub file
///
/// # Returns
///
/// SSH public key in OpenSSH format (e.g., "ssh-ed25519 AAAA...")
///
/// # Errors
///
/// Returns error if:
/// - File cannot be read
/// - File is empty or contains invalid UTF-8
/// - Key type is not ssh-ed25519
pub fn load_ssh_public_key_file(pub_key_path: &Path) -> Result<String> {
    let content = load_text_with_limit(
        pub_key_path,
        MAX_SSH_PUBLIC_KEY_FILE_SIZE,
        "SSH public key file",
    )
    .map_err(|error| {
        let message = format!(
            "Failed to read public key file {}: {}",
            format_path_relative_to_cwd(pub_key_path),
            error
        );
        ssh_error(message)
    })?;

    let pubkey = content.trim().to_string();

    // Validate key type is ssh-ed25519
    let key_type = pubkey.split_whitespace().next().ok_or_else(|| {
        ssh_error(format!(
            "Invalid public key format in {}: empty or missing key type",
            format_path_relative_to_cwd(pub_key_path)
        ))
    })?;

    if key_type != ssh::KEY_TYPE_ED25519 {
        return Err(ssh_error(format!(
            "Unsupported key type in {}: found '{}', expected '{}'\n\
            Only Ed25519 keys are supported.",
            format_path_relative_to_cwd(pub_key_path),
            key_type,
            ssh::KEY_TYPE_ED25519
        )));
    }

    Ok(pubkey)
}

/// Load SSH public key using a key descriptor via the `SshKeygen` trait.
///
/// For private keys: Derives the public key via `ssh_keygen.derive_public_key()`
/// For public keys: Reads the key directly from the .pub file
pub fn load_ssh_public_key_with_descriptor_trait(
    ssh_keygen: &dyn SshKeygen,
    key_descriptor: &SshKeyDescriptor,
) -> Result<String> {
    match key_descriptor {
        SshKeyDescriptor::PrivateKey(private_key) => {
            ssh_keygen.derive_public_key(private_key.as_path())
        }
        SshKeyDescriptor::PublicKey(public_key) => load_ssh_public_key_file(public_key.as_path()),
    }
}

/// Collect all Ed25519 key lines from ssh-add -L output.
///
/// Returns trimmed lines whose key type is `ssh-ed25519`.
pub fn collect_ed25519_keys_in_output(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|line| {
            line.split_whitespace()
                .next()
                .is_some_and(|t| t == ssh::KEY_TYPE_ED25519)
        })
        .map(|line| line.trim().to_string())
        .collect()
}

/// Load all Ed25519 keys from the SSH agent as candidates.
///
/// Calls `ssh_add.list_keys()`, filters for Ed25519 keys, and builds
/// an `SshKeyCandidate` for each by computing the fingerprint and
/// extracting the comment.
pub fn load_ed25519_keys_from_agent(ssh_add: &dyn SshAdd) -> Result<Vec<SshKeyCandidate>> {
    let output = ssh_add.list_keys()?;
    let lines = collect_ed25519_keys_in_output(&output);
    lines
        .into_iter()
        .map(|line| build_candidate_from_line(&line))
        .collect()
}

/// Load an SSH key candidate from a file-based key descriptor.
///
/// Derives the public key via `load_ssh_public_key_with_descriptor_trait`,
/// then computes fingerprint and extracts comment.
pub fn load_ssh_key_candidate_from_file(
    ssh_keygen: &dyn SshKeygen,
    descriptor: &SshKeyDescriptor,
) -> Result<SshKeyCandidate> {
    let public_key = load_ssh_public_key_with_descriptor_trait(ssh_keygen, descriptor)?;
    build_candidate_from_line(&public_key)
}

/// Build an `SshKeyCandidate` from a single OpenSSH public key line.
fn build_candidate_from_line(line: &str) -> Result<SshKeyCandidate> {
    let fingerprint = build_sha256_fingerprint(line)?;
    let comment = extract_comment(line);
    Ok(SshKeyCandidate {
        public_key: line.to_string(),
        fingerprint,
        comment,
    })
}

/// Extract the trailing comment from an OpenSSH public key line.
///
/// Format: `key_type base64_data [comment]`
/// The comment is everything after the second whitespace-delimited field.
fn extract_comment(line: &str) -> String {
    let mut parts = line.splitn(3, char::is_whitespace);
    // skip key_type and base64_data
    parts.next();
    parts.next();
    parts
        .next()
        .map(|c| c.trim().to_string())
        .unwrap_or_default()
}
