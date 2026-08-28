// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! DoS protection limits.

use crate::{Error, Result};
use std::path::Path;
use std::time::Duration;

/// Maximum number of WRAP items per document
pub const MAX_WRAP_ITEMS: usize = 1_000;

/// How long a directory lock acquisition waits before giving up.
///
/// `flock` has no timed form, so a contended lock is retried until this bound
/// and then reported. Waiting without a bound turns a lock somebody left behind
/// into a command that never returns and never says what it is waiting for.
pub const DIRECTORY_LOCK_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(30);

/// Shortest pause between two attempts at a contended directory lock.
pub const DIRECTORY_LOCK_RETRY_MIN_INTERVAL: Duration = Duration::from_millis(5);

/// Longest pause the retry backoff grows to.
pub const DIRECTORY_LOCK_RETRY_MAX_INTERVAL: Duration = Duration::from_millis(200);

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

/// Maximum member handle length in bytes.
///
/// A member handle names its own file as `<handle>.json` in the local trust
/// store and in the workspace member directory, so it has to fit what an atomic
/// write can target once the staging suffix is accounted for. This bound sits
/// well inside that budget instead of at its edge, so a later change to the
/// staging overhead does not turn handles that are already registered into
/// handles that fail at their next write.
pub const MAX_MEMBER_HANDLE_LENGTH: usize = 128;

/// A handle longer than an atomic write can target would be accepted at
/// registration and then refused at its first write, so the remaining budget is
/// checked when the crate is built rather than when a handle is stored.
const _: () = assert!(
    MAX_MEMBER_HANDLE_LENGTH + JSON_EXTENSION_LENGTH <= MAX_ATOMIC_WRITE_TARGET_NAME_LENGTH
);

/// Bytes the `.json` suffix adds to a handle used as a file name.
const JSON_EXTENSION_LENGTH: usize = 5;

/// Maximum length of a file name an atomic write may target.
///
/// An atomic write stages its content under `.{target}.tmp.{uuid}` before the
/// rename, which adds a fixed overhead to the target name. Without this bound a
/// target that fits `NAME_MAX` on its own can still fail at the staging step, so
/// the overhead is subtracted up front and reported against the target instead.
pub const MAX_ATOMIC_WRITE_TARGET_NAME_LENGTH: usize =
    MAX_FILE_NAME_LENGTH - ATOMIC_WRITE_TEMP_NAME_OVERHEAD;

/// Longest file name a POSIX directory entry accepts.
const MAX_FILE_NAME_LENGTH: usize = 255;

/// Bytes `.{target}.tmp.{uuid}` adds around the target name: a leading dot, the
/// `.tmp.` separator and a hyphenated UUID.
const ATOMIC_WRITE_TEMP_NAME_OVERHEAD: usize = 1 + 5 + 36;

/// Maximum GitHub API response body size in bytes.
#[cfg(feature = "online")]
pub const MAX_GITHUB_RESPONSE_SIZE: usize = 1024 * 1024;

/// Maximum number of KEY lines in a kv-enc document
pub const MAX_KV_KEY_LINES: usize = 10_000;

/// Maximum length of a single base64url token in bytes
pub const MAX_BASE64_TOKEN_LENGTH: usize = 1024 * 1024;

/// Maximum length of base64url ciphertext in bytes (16 MiB)
pub const MAX_BASE64_CIPHERTEXT_LENGTH: usize = 16 * 1024 * 1024;

/// Maximum plaintext input size in bytes for encryption.
///
/// A plaintext is sealed and the ciphertext is carried as base64url, which
/// grows every three bytes into four. A larger input therefore produces a token
/// past [`MAX_BASE64_CIPHERTEXT_LENGTH`], and the document it yields could
/// never be read back. The bound is derived from that limit and applied to the
/// input the operator hands over, so the refusal names the file they chose
/// rather than a token they never saw.
pub const MAX_PLAINTEXT_INPUT_SIZE: usize = MAX_BASE64_CIPHERTEXT_LENGTH / 4 * 3 - AEAD_TAG_LENGTH;

/// Bytes the AEAD tag adds to a sealed plaintext.
const AEAD_TAG_LENGTH: usize = 16;

/// Maximum JSON nesting depth
pub const MAX_JSON_DEPTH: usize = 32;

/// JSON elements one wrap item contributes: the object, its five member
/// separators, and the comma that joins it to the next item.
const JSON_ELEMENTS_PER_WRAP_ITEM: usize = 11;

/// Element budget for the document structure outside the wrap array.
const JSON_ELEMENTS_DOCUMENT_OVERHEAD: usize = 2_000;

/// Maximum number of JSON elements (objects + arrays + values)
///
/// Derived from [`MAX_WRAP_ITEMS`] so a document carrying the documented
/// maximum number of recipients stays reachable. A fixed value smaller than
/// this budget rejects such documents in the pre-parse scan, before the wrap
/// count limit is ever consulted.
pub const MAX_JSON_ELEMENTS: usize =
    MAX_WRAP_ITEMS * JSON_ELEMENTS_PER_WRAP_ITEM + JSON_ELEMENTS_DOCUMENT_OVERHEAD;

/// Validate WRAP item count against the global DoS limit.
pub fn validate_wrap_count(count: usize, context: &str) -> Result<()> {
    if count <= MAX_WRAP_ITEMS {
        return Ok(());
    }

    Err(Error::build_parse_error(format!(
        "{} exceeds maximum wrap count ({} > {})",
        context, count, MAX_WRAP_ITEMS
    )))
}

/// Resolve a pre-read size limit for encrypted artifact paths.
pub fn resolve_encrypted_artifact_read_limit(path: &Path) -> usize {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("kvenc") => MAX_KV_ENC_FILE_SIZE,
        _ => MAX_JSON_DOCUMENT_READ_SIZE,
    }
}
