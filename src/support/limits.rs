// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! DoS protection limits.

use crate::{Error, Result};
use std::path::Path;

/// Maximum number of WRAP items per document
pub const MAX_WRAP_ITEMS: usize = 1_000;

/// Maximum kv-enc file size in bytes (16 MiB)
pub const MAX_KV_ENC_FILE_SIZE: usize = 16 * 1024 * 1024;

/// Maximum JSON document file size in bytes for pre-read validation.
pub const MAX_JSON_DOCUMENT_READ_SIZE: usize = 24 * 1024 * 1024;

/// Maximum SSH public key file size in bytes.
pub const MAX_SSH_PUBLIC_KEY_FILE_SIZE: usize = 64 * 1024;

/// Maximum OpenSSH config file size in bytes.
pub const MAX_SSH_CONFIG_FILE_SIZE: usize = 1024 * 1024;

/// Maximum global config.toml size in bytes.
pub const MAX_CONFIG_FILE_SIZE: usize = 1024 * 1024;

/// Maximum active kid file size in bytes.
pub const MAX_ACTIVE_KID_FILE_SIZE: usize = 256;

/// Maximum number of KEY lines in a kv-enc document
pub const MAX_KV_KEY_LINES: usize = 10_000;

/// Maximum length of a single base64url token in bytes
pub const MAX_BASE64_TOKEN_LENGTH: usize = 1024 * 1024;

/// Maximum length of base64url ciphertext in bytes (16 MiB)
pub const MAX_BASE64_CIPHERTEXT_LENGTH: usize = 16 * 1024 * 1024;

/// Maximum JSON nesting depth
pub const MAX_JSON_DEPTH: usize = 32;

/// Maximum number of JSON elements (objects + arrays + values)
pub const MAX_JSON_ELEMENTS: usize = 10_000;

/// Validate WRAP item count against the global DoS limit.
pub fn validate_wrap_count(count: usize, context: &str) -> Result<()> {
    if count <= MAX_WRAP_ITEMS {
        return Ok(());
    }

    Err(Error::Parse {
        message: format!(
            "{} exceeds maximum wrap count ({} > {})",
            context, count, MAX_WRAP_ITEMS
        ),
        source: None,
    })
}

/// Resolve a pre-read size limit for encrypted artifact paths.
pub fn resolve_encrypted_artifact_read_limit(path: &Path) -> usize {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("kvenc") => MAX_KV_ENC_FILE_SIZE,
        _ => MAX_JSON_DOCUMENT_READ_SIZE,
    }
}
