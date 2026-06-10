// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH public key parsing helpers (pure).

use super::constants::KEY_TYPE_ED25519;
use crate::format::codec::base64_public::decode_base64_standard;
use crate::io::ssh::SshError;
use crate::Result;

/// Decode the base64 key blob from an OpenSSH public key line.
///
/// Expected format: `ssh-ed25519 <base64_blob> [comment]`
pub fn decode_ssh_public_key_blob(ssh_pubkey: &str) -> Result<Vec<u8>> {
    let line = ssh_pubkey.trim();
    if line.is_empty() {
        return Err(SshError::build_operation_failed_error("Public key line is empty").into());
    }

    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 2 {
        return Err(SshError::build_operation_failed_error(format!(
            "Invalid public key format: {}",
            line
        ))
        .into());
    }

    let key_type = fields[0];
    if key_type != KEY_TYPE_ED25519 {
        return Err(SshError::build_operation_failed_error(format!(
            "Unsupported key type '{}': v1 only supports {}",
            key_type, KEY_TYPE_ED25519
        ))
        .into());
    }

    decode_base64_standard(fields[1], "base64").map_err(|e| {
        crate::Error::from(SshError::build_operation_failed_error_with_source(
            format!("Failed to decode base64: {}", e),
            e,
        ))
    })
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/ssh_parse_test.rs"]
mod ssh_parse_test;
