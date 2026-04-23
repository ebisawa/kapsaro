// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Atomic filesystem operations.

pub mod atomic;
pub mod lock;

use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use std::fs;
use std::fs::{File, ReadDir};
use std::io::Read;
use std::path::Path;

/// Read a file as bytes with consistent path-aware error messages.
pub fn load_bytes(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| {
        Error::io_with_source(
            format!(
                "Failed to read file {}: {}",
                display_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })
}

/// Read a file as bytes with a streaming size cap.
///
/// Refuses symlinks and non-regular files (FIFO, device, socket, directory)
/// and never reads more than `max_bytes + 1` bytes, so adversarial FIFOs or
/// character devices cannot make the read hang or exhaust memory.
pub fn load_bytes_with_limit(path: &Path, max_bytes: usize, subject: &str) -> Result<Vec<u8>> {
    let mut file = open_regular_file(path)?;
    read_capped(&mut file, max_bytes, subject, path)
}

/// Read a UTF-8 text file with consistent path-aware error messages.
pub fn load_text(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|e| {
        Error::io_with_source(
            format!(
                "Failed to read file {}: {}",
                display_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })
}

/// Read a UTF-8 text file with a pre-read size limit.
pub fn load_text_with_limit(path: &Path, max_bytes: usize, subject: &str) -> Result<String> {
    let bytes = load_bytes_with_limit(path, max_bytes, subject)?;
    String::from_utf8(bytes).map_err(|e| Error::Parse {
        message: format!(
            "Failed to read file {}: {}",
            display_path_relative_to_cwd(path),
            e
        ),
        source: Some(Box::new(e)),
    })
}

/// Validate that a text file still matches its reviewed snapshot.
///
/// `subject_display` should already contain the user-facing subject, such as
/// `KV file '/path/to/file'` or `Incoming member 'alice@example.com'`.
pub fn ensure_text_file_matches_snapshot(
    path: &Path,
    reviewed_content: Option<&str>,
    subject_display: &str,
) -> Result<()> {
    match reviewed_content {
        Some(reviewed_content) => {
            let current = fs::read_to_string(path).map_err(|e| Error::InvalidOperation {
                message: format!(
                    "{} changed since review: failed to read current file ({})",
                    subject_display, e
                ),
            })?;
            if current == reviewed_content {
                return Ok(());
            }
        }
        None => {
            if !path.exists() {
                return Ok(());
            }
        }
    }

    Err(Error::InvalidOperation {
        message: format!(
            "{} changed since review and must be reviewed again.",
            subject_display
        ),
    })
}

/// List directory entries with consistent path-aware error messages.
pub fn list_dir(path: &Path) -> Result<ReadDir> {
    fs::read_dir(path).map_err(|e| {
        Error::io_with_source(
            format!(
                "Failed to read directory {}: {}",
                display_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })
}

/// Ensure a directory exists with consistent path-aware error messages.
pub fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|e| {
        Error::io_with_source(
            format!(
                "Failed to create directory {}: {}",
                display_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })
}

/// Ensure a directory exists with restricted permissions (mode 0700 on Unix).
///
/// Creates the directory recursively if it does not exist. If the directory
/// already exists, its permissions are corrected to 0700.
#[cfg(unix)]
pub fn ensure_dir_restricted(path: &Path) -> Result<()> {
    use std::fs::{DirBuilder, Permissions};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|e| {
            Error::io_with_source(
                format!(
                    "Failed to create directory {}: {}",
                    display_path_relative_to_cwd(path),
                    e
                ),
                e,
            )
        })?;

    fs::set_permissions(path, Permissions::from_mode(0o700)).map_err(|e| {
        Error::io_with_source(
            format!(
                "Failed to set permissions on {}: {}",
                display_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })
}

/// Ensure a directory exists with restricted permissions (non-Unix fallback).
#[cfg(not(unix))]
pub fn ensure_dir_restricted(path: &Path) -> Result<()> {
    ensure_dir(path)
}

/// Set file permissions to 0600 (owner read/write only) on Unix.
#[cfg(unix)]
pub fn set_file_permission_0600(path: &Path) -> Result<()> {
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, Permissions::from_mode(0o600)).map_err(|e| {
        Error::io_with_source(
            format!(
                "Failed to set permissions on {}: {}",
                display_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })
}

/// Set file permissions to 0600 (non-Unix fallback).
#[cfg(not(unix))]
pub fn set_file_permission_0600(_path: &Path) -> Result<()> {
    Ok(())
}

/// Check whether a path has overly permissive permissions.
///
/// Returns `Some(warning_message)` if the path is insecure or cannot be
/// checked, `None` if permissions are acceptable.
#[cfg(unix)]
pub fn check_permission(path: &Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            return Some(format!(
                "Cannot check permissions on {}: {}",
                display_path_relative_to_cwd(path),
                e
            ));
        }
    };
    let mode = metadata.permissions().mode();
    let extra_bits = mode & 0o077;
    if extra_bits != 0 {
        let expected = if metadata.is_dir() { "0700" } else { "0600" };
        Some(format!(
            "Insecure permissions {:04o} on {} (expected {})",
            mode & 0o777,
            display_path_relative_to_cwd(path),
            expected,
        ))
    } else {
        None
    }
}

#[cfg(unix)]
pub fn check_permission_chain(path: &Path, logical_root: &Path) -> Vec<String> {
    if !path.starts_with(logical_root) {
        return vec![format!(
            "Cannot check permissions on {}: path is outside logical root {}",
            display_path_relative_to_cwd(path),
            display_path_relative_to_cwd(logical_root)
        )];
    }

    let mut warnings = Vec::new();
    warnings.extend(check_permission(logical_root));

    let mut current = logical_root.to_path_buf();
    let Ok(relative_path) = path.strip_prefix(logical_root) else {
        return warnings;
    };

    for component in relative_path.components() {
        current.push(component.as_os_str());
        if let Some(warning) = check_permission(&current) {
            warnings.push(warning);
        }
    }

    warnings
}

#[cfg(not(unix))]
pub fn check_permission_chain(_path: &Path, _logical_root: &Path) -> Vec<String> {
    Vec::new()
}

/// Open a path as a regular file, rejecting symlinks, FIFOs, devices, sockets,
/// and directories.
///
/// A `symlink_metadata` pre-check rejects symlinks and any non-regular file
/// type before calling `open`, because opening a FIFO without `O_NONBLOCK`
/// would block until a writer appears. On Unix the open itself adds
/// `O_NOFOLLOW | O_NONBLOCK` to close the final-component swap race without
/// blocking if the swap produced a FIFO. A post-open `file_type()` check
/// rejects anything that slipped through the race. A residual TOCTOU window
/// on intermediate path components is accepted: anyone with write on the
/// parent is already inside the local-adversary threat model.
fn open_regular_file(path: &Path) -> Result<File> {
    let pre_meta = fs::symlink_metadata(path).map_err(|e| {
        Error::io_with_source(
            format!(
                "Failed to read file {}: {}",
                display_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })?;
    let pre_ty = pre_meta.file_type();
    if pre_ty.is_symlink() {
        return Err(Error::InvalidOperation {
            message: format!(
                "refusing to read symlink: {}",
                display_path_relative_to_cwd(path)
            ),
        });
    }
    if !pre_ty.is_file() {
        return Err(Error::InvalidOperation {
            message: format!(
                "refusing to read non-regular file: {}",
                display_path_relative_to_cwd(path)
            ),
        });
    }

    let file = open_no_follow(path)?;

    let post_meta = file.metadata().map_err(|e| {
        Error::io_with_source(
            format!(
                "Failed to read file {}: {}",
                display_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })?;
    if !post_meta.file_type().is_file() {
        return Err(Error::InvalidOperation {
            message: format!(
                "refusing to read non-regular file: {}",
                display_path_relative_to_cwd(path)
            ),
        });
    }

    Ok(file)
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| {
            Error::io_with_source(
                format!(
                    "Failed to read file {}: {}",
                    display_path_relative_to_cwd(path),
                    e
                ),
                e,
            )
        })
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> Result<File> {
    fs::File::open(path).map_err(|e| {
        Error::io_with_source(
            format!(
                "Failed to read file {}: {}",
                display_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })
}

/// Read up to `max_bytes` from `file` via a streaming cap.
///
/// Uses `Read::take(max + 1)` so a file whose metadata lies (e.g., FIFO
/// reporting length 0) or that yields unbounded output (e.g., `/dev/zero`)
/// cannot exhaust memory: at most `max_bytes + 1` bytes are read before the
/// size check fires.
fn read_capped(file: &mut File, max_bytes: usize, subject: &str, path: &Path) -> Result<Vec<u8>> {
    let initial = std::cmp::min(max_bytes.saturating_add(1), 64 * 1024);
    let mut buf = Vec::with_capacity(initial);
    let cap = (max_bytes as u64).saturating_add(1);
    file.take(cap).read_to_end(&mut buf).map_err(|e| {
        Error::io_with_source(
            format!(
                "Failed to read file {}: {}",
                display_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })?;
    validate_loaded_size(path, buf.len(), max_bytes, subject)?;
    Ok(buf)
}

fn validate_loaded_size(path: &Path, size: usize, max_bytes: usize, subject: &str) -> Result<()> {
    if size <= max_bytes {
        return Ok(());
    }

    Err(Error::Parse {
        message: format!(
            "{} exceeds maximum size limit ({} bytes > {} bytes): {}",
            subject,
            size,
            max_bytes,
            display_path_relative_to_cwd(path)
        ),
        source: None,
    })
}

/// Check whether a path has overly permissive permissions (non-Unix fallback).
#[cfg(not(unix))]
pub fn check_permission(_path: &Path) -> Option<String> {
    None
}
