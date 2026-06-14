// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File locking utilities.

use super::relative::{DirectoryFd, OpenDir};
use crate::support::fs::policy::{
    enforce_path_not_symlink, ensure_real_directory_tree, DirectoryMode, DirectoryPurpose,
};
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use fd_lock::RwLock;
use std::fs::{File, OpenOptions};
use std::path::Path;

#[derive(Debug)]
pub(crate) struct LockedDir<'a> {
    file: &'a File,
    path: &'a Path,
}

impl DirectoryFd for LockedDir<'_> {
    fn file(&self) -> &File {
        self.file
    }

    fn path(&self) -> &Path {
        self.path
    }
}

impl LockedDir<'_> {
    #[cfg(unix)]
    pub(crate) fn open_child_dir(&self, name: &str) -> Result<OpenDir> {
        super::relative::open_child_dir(self, name)
    }
}

/// Execute a function with an exclusive file lock.
///
/// Creates a sidecar lock file (`.{filename}.lock`) in the same directory as the target
/// file and holds an exclusive lock while executing the provided function. The sidecar
/// is deliberately kept on disk after release so that all processes contending for the
/// same logical target always open fds to the same underlying inode (rendezvous anchor).
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
    // This is required for cases like `kapsaro config set ...` where
    // KAPSARO_HOME/config.toml's parent directory may not be created yet.
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

    let result = {
        let _guard = lock
            .write()
            .map_err(|e| Error::build_io_error(format!("Failed to acquire lock: {}", e)))?;
        f()
    };

    // NOTE: We deliberately do *not* remove the sidecar lock file here.
    // The persistent name acts as the rendezvous point so that all processes
    // contending for the same logical target (e.g. a .kvenc file) open fds
    // to the *same* underlying inode. Deleting the name after release allows
    // a late-arriving process to create a fresh lock file (new inode) and
    // acquire independently, breaking mutual exclusion for the protected
    // operation (see detailed race analysis in conversation history).
    // The lock file may remain on disk after use; use .gitignore for
    // `.*.lock` patterns in workspace secrets/ etc. as needed.
    result
}

/// Execute a function with an exclusive directory lock.
///
/// Locks the given directory itself (no sidecar file is created).
/// The directory must already exist; this function does not create it.
/// The lock is released when the returned guard is dropped after `f` returns.
///
/// On Unix, the directory fd is opened with `O_DIRECTORY | O_NOFOLLOW` so that
/// a symlink at the final path component is rejected before locking.
pub fn with_dir_lock<T, F>(dir: &Path, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    with_locked_dir(dir, |_| f())
}

/// Execute a function with an exclusive directory lock and the locked fd.
pub(crate) fn with_locked_dir<T, F>(dir: &Path, f: F) -> Result<T>
where
    F: FnOnce(&LockedDir<'_>) -> Result<T>,
{
    enforce_path_not_symlink(dir, |path| {
        format!("refusing to lock directory through symlink: {}", path)
    })?;

    let dir_file = open_dir_for_locking(dir)?;
    let mut lock = RwLock::new(dir_file);

    let guard = lock
        .write()
        .map_err(|e| Error::build_io_error(format!("Failed to acquire directory lock: {}", e)))?;

    let locked = LockedDir {
        file: &guard,
        path: dir,
    };
    f(&locked)
}

#[cfg(unix)]
fn open_dir_for_locking(dir: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
        .map_err(|e| {
            Error::build_io_error_with_source(
                format!(
                    "Failed to open directory for locking: {}",
                    format_path_relative_to_cwd(dir)
                ),
                e,
            )
        })
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

#[cfg(test)]
#[path = "../../../tests/unit/internal/support_fs_lock_error_test.rs"]
mod support_fs_lock_error_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/support_fs_lock_test.rs"]
mod support_fs_lock_test;
