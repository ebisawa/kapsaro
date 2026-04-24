// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File locking utilities.

use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use fd_lock::RwLock;
use std::fs;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

/// Execute a function with an exclusive file lock.
///
/// Creates a lock file (`.{filename}.lock`) in the same directory as the target file
/// and holds an exclusive lock while executing the provided function.
pub fn with_file_lock<T, F>(path: &Path, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let file_name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        Error::build_io_error(format!(
            "Invalid file path: {}",
            format_path_relative_to_cwd(path)
        ))
    })?;
    let lock_file_name = format!(".{}.lock", file_name);
    let lock_path = lock_parent_dir(path)
        .map(|parent| parent.join(&lock_file_name))
        .unwrap_or_else(|| Path::new(&lock_file_name).to_path_buf());

    // Ensure the directory exists before opening the lock file.
    // This is required for cases like `secretenv config set ...` where
    // SECRETENV_HOME/config.toml's parent directory may not be created yet.
    if let Some(lock_parent) = lock_parent_dir(&lock_path) {
        ensure_lock_parent_dir(lock_parent)?;
    }
    enforce_lock_path_not_symlink(&lock_path)?;

    let lock_file = {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        opts.open(&lock_path).map_err(|e| {
            Error::build_io_error_with_source(format!("Failed to open lock file: {}", e), e)
        })?
    };

    let mut lock = RwLock::new(lock_file);
    let _guard = lock
        .write()
        .map_err(|e| Error::build_io_error(format!("Failed to acquire lock: {}", e)))?;

    f()
}

fn lock_parent_dir(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty() && *parent != Path::new("."))
}

fn ensure_lock_parent_dir(path: &Path) -> Result<()> {
    for missing_dir in collect_missing_directories(path)?.into_iter().rev() {
        ensure_lock_directory(&missing_dir)?;
    }
    Ok(())
}

fn enforce_lock_path_not_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::InvalidOperation {
            message: format!(
                "refusing to create lock file through symlink: {}",
                format_path_relative_to_cwd(path)
            ),
        }),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::build_io_error_with_source(
            format!(
                "Failed to inspect lock file {}: {}",
                format_path_relative_to_cwd(path),
                e
            ),
            e,
        )),
    }
}

fn collect_missing_directories(path: &Path) -> Result<Vec<PathBuf>> {
    let mut missing = Vec::new();

    for ancestor in path.ancestors() {
        let candidate = if ancestor.as_os_str().is_empty() {
            Path::new(".")
        } else {
            ancestor
        };
        match fs::symlink_metadata(candidate) {
            Ok(metadata) => {
                validate_real_directory(candidate, &metadata)?;
                return Ok(missing);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                missing.push(candidate.to_path_buf());
            }
            Err(e) => {
                return Err(Error::build_io_error_with_source(
                    format!(
                        "Failed to inspect lock file directory {}: {}",
                        format_path_relative_to_cwd(candidate),
                        e
                    ),
                    e,
                ));
            }
        }
    }

    Err(Error::build_io_error(format!(
        "Failed to resolve parent directory for lock file: {}",
        format_path_relative_to_cwd(path)
    )))
}

fn validate_real_directory(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(Error::InvalidOperation {
            message: format!(
                "refusing to create lock file in symlinked directory: {}",
                format_path_relative_to_cwd(path)
            ),
        });
    }
    if !file_type.is_dir() {
        return Err(Error::build_io_error(format!(
            "Failed to create directory for lock file '{}': existing path is not a directory",
            format_path_relative_to_cwd(path)
        )));
    }
    Ok(())
}

fn ensure_lock_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::{DirBuilder, Permissions};
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        DirBuilder::new().mode(0o700).create(path).map_err(|e| {
            Error::build_io_error_with_source(
                format!(
                    "Failed to create directory for lock file '{}': {}",
                    format_path_relative_to_cwd(path),
                    e
                ),
                e,
            )
        })?;
        fs::set_permissions(path, Permissions::from_mode(0o700)).map_err(|e| {
            Error::build_io_error_with_source(
                format!(
                    "Failed to set permissions on {}: {}",
                    format_path_relative_to_cwd(path),
                    e
                ),
                e,
            )
        })?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        fs::create_dir(path).map_err(|e| {
            Error::build_io_error_with_source(
                format!(
                    "Failed to create directory for lock file '{}': {}",
                    format_path_relative_to_cwd(path),
                    e
                ),
                e,
            )
        })
    }
}
