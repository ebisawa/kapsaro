// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File locking utilities.

use crate::support::fs::policy::{
    enforce_path_not_symlink, ensure_real_directory_tree, DirectoryMode, DirectoryPurpose,
};
use crate::support::path::format_path_relative_to_cwd;
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
    ensure_real_directory_tree(path, DirectoryPurpose::LockFile, DirectoryMode::Restricted)
}

fn enforce_lock_path_not_symlink(path: &Path) -> Result<()> {
    enforce_path_not_symlink(path, |path| {
        format!("refusing to create lock file through symlink: {}", path)
    })
}
