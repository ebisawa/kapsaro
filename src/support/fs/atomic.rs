// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Atomic file write operations.

use crate::support::fs::{ensure_dir_restricted, set_file_permission_0600};
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use serde::Serialize;
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

/// Reject a write whose parent directory is a symlink.
///
/// The write itself uses `NamedTempFile::new_in(parent).persist(target)`,
/// which resolves `parent` as the OS sees it. If `parent` is a symlink to
/// somewhere else, the atomic rename lands outside the caller's intended
/// directory. Callers pass a workspace-derived parent, so a symlink here
/// indicates the workspace has been tampered with.
fn reject_symlinked_parent(parent: &Path) -> Result<()> {
    match fs::symlink_metadata(parent) {
        Ok(meta) if meta.file_type().is_symlink() => Err(Error::InvalidOperation {
            message: format!(
                "refusing to write: parent directory is a symlink: {}",
                display_path_relative_to_cwd(parent)
            ),
        }),
        _ => Ok(()),
    }
}

/// Reject a write whose target path is already a symlink.
///
/// `persist` would follow the symlink and overwrite its target. For paths
/// that live inside a non-trusted workspace this is the same escape vector
/// as a symlinked parent.
fn reject_symlinked_target(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(Error::InvalidOperation {
            message: format!(
                "refusing to write: target is a symlink: {}",
                display_path_relative_to_cwd(path)
            ),
        }),
        _ => Ok(()),
    }
}

/// Ensure parent directory exists
fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            Error::io_with_source(
                format!(
                    "Failed to create directory {}: {}",
                    display_path_relative_to_cwd(parent),
                    e
                ),
                e,
            )
        })?;
    }
    Ok(())
}

/// Ensure parent directory exists with restricted permissions (mode 0700)
fn ensure_parent_dir_restricted(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir_restricted(parent)?;
    }
    Ok(())
}

/// Save JSON data atomically (write-then-rename)
pub fn save_json<T: Serialize>(path: &Path, data: &T) -> Result<()> {
    ensure_parent_dir(path)?;
    let json = serde_json::to_string_pretty(data).map_err(|e| Error::Parse {
        message: format!("JSON serialization failed: {}", e),
        source: Some(Box::new(e)),
    })?;
    save_bytes(path, json.as_bytes())
}

/// Save text content atomically
pub fn save_text(path: &Path, content: &str) -> Result<()> {
    ensure_parent_dir(path)?;
    save_bytes(path, content.as_bytes())
}

/// Save JSON data atomically with restricted permissions (dir 0700, file 0600)
pub fn save_json_restricted<T: Serialize>(path: &Path, data: &T) -> Result<()> {
    ensure_parent_dir_restricted(path)?;
    let json = serde_json::to_string_pretty(data).map_err(|e| Error::Parse {
        message: format!("JSON serialization failed: {}", e),
        source: Some(Box::new(e)),
    })?;
    save_bytes(path, json.as_bytes())?;
    set_file_permission_0600(path)
}

/// Save text content atomically with restricted permissions (dir 0700, file 0600)
pub fn save_text_restricted(path: &Path, content: &str) -> Result<()> {
    ensure_parent_dir_restricted(path)?;
    save_bytes(path, content.as_bytes())?;
    set_file_permission_0600(path)
}

/// Save bytes atomically.
///
/// Refuses to write when either `path` itself or its parent directory is a
/// symlink, so that an adversary cannot redirect writes out of a verified
/// workspace by planting a symlink at `members/active/` or `secrets/`.
pub fn save_bytes(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    reject_symlinked_parent(parent)?;
    reject_symlinked_target(path)?;
    let mut temp = NamedTempFile::new_in(parent)
        .map_err(|e| Error::io_with_source(format!("Failed to create temp file: {}", e), e))?;

    temp.write_all(data)
        .map_err(|e| Error::io_with_source(format!("Write failed: {}", e), e))?;

    temp.flush()
        .map_err(|e| Error::io_with_source(format!("Flush failed: {}", e), e))?;

    temp.persist(path).map_err(|e| {
        Error::io_with_source(
            format!(
                "Persist to {} failed: {}",
                display_path_relative_to_cwd(path),
                e.error
            ),
            e.error,
        )
    })?;

    Ok(())
}
