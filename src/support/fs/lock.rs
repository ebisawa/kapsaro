// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File locking utilities.

use crate::support::fs::ensure_dir_restricted;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use fd_lock::RwLock;
use std::fs::OpenOptions;
use std::path::Path;

/// Execute a function with an exclusive file lock.
///
/// Creates a lock file (`.{filename}.lock`) in the same directory as the target file
/// and holds an exclusive lock while executing the provided function.
pub fn with_file_lock<T, F>(path: &Path, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let file_name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
        Error::io(format!(
            "Invalid file path: {}",
            display_path_relative_to_cwd(path)
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
        ensure_dir_restricted(lock_parent).map_err(|e| {
            Error::io(format!(
                "Failed to create directory for lock file '{}': {}",
                display_path_relative_to_cwd(lock_parent),
                e
            ))
        })?;
    }

    let lock_file = {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(&lock_path)
            .map_err(|e| Error::io_with_source(format!("Failed to open lock file: {}", e), e))?
    };

    let mut lock = RwLock::new(lock_file);
    let _guard = lock
        .write()
        .map_err(|e| Error::io(format!("Failed to acquire lock: {}", e)))?;

    f()
}

fn lock_parent_dir(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty() && *parent != Path::new("."))
}
