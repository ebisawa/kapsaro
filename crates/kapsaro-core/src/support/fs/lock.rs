// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Short-lived exclusive directory locking for destructive local transactions.
//! Prevents accidental writer conflicts on one host without gating readers.

use super::anchor::AnchoredDir;
use super::relative::{file_identity, DirectoryFd, DirectoryScope, EntryIdentity, OpenDir};
use crate::support::limits::{
    DIRECTORY_LOCK_ACQUIRE_TIMEOUT, DIRECTORY_LOCK_RETRY_MAX_INTERVAL,
    DIRECTORY_LOCK_RETRY_MIN_INTERVAL,
};
use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
#[cfg(unix)]
use std::cell::RefCell;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[cfg(unix)]
use rustix::fs::{FlockOperation, OFlags};
#[cfg(unix)]
use rustix::io::Errno;

#[derive(Debug)]
pub(crate) struct ExclusiveLockedDir<'a> {
    file: &'a File,
    path: &'a Path,
    scope: DirectoryScope,
}

mod private {
    pub trait LockTargetSealed {}
}

pub(crate) trait LockTargetDirectory: DirectoryFd + private::LockTargetSealed {}

impl DirectoryFd for ExclusiveLockedDir<'_> {
    fn file(&self) -> &File {
        self.file
    }

    fn path(&self) -> &Path {
        self.path
    }

    fn scope(&self) -> DirectoryScope {
        self.scope
    }
}

impl private::LockTargetSealed for OpenDir {}
impl private::LockTargetSealed for AnchoredDir {}
impl LockTargetDirectory for OpenDir {}
impl LockTargetDirectory for AnchoredDir {}

#[cfg(unix)]
thread_local! {
    static HELD_DIRECTORY_LOCKS: RefCell<Vec<HeldLock>> = const { RefCell::new(Vec::new()) };
}

#[cfg(unix)]
struct HeldLock {
    identity: EntryIdentity,
    path: PathBuf,
}

#[cfg(unix)]
struct HeldDirectory {
    file: File,
    identity: EntryIdentity,
}

#[cfg(unix)]
impl HeldDirectory {
    fn claim(file: File, identity: EntryIdentity, path: &Path) -> Result<Self> {
        HELD_DIRECTORY_LOCKS.with(|held| {
            let mut held = held.borrow_mut();
            if let Some(current) = held.first() {
                return Err(nested_lock_error(path, &current.path));
            }
            held.push(HeldLock {
                identity,
                path: path.to_path_buf(),
            });
            Ok(())
        })?;
        Ok(Self { file, identity })
    }
}

#[cfg(unix)]
impl Drop for HeldDirectory {
    fn drop(&mut self) {
        HELD_DIRECTORY_LOCKS.with(|held| {
            held.borrow_mut()
                .retain(|entry| entry.identity != self.identity);
        });
    }
}

/// Lock one opened directory exclusively for a short mutation transaction.
#[cfg(unix)]
pub(crate) fn with_exclusive_locked_directory<T, D, F>(dir: &D, f: F) -> Result<T>
where
    D: LockTargetDirectory,
    F: FnOnce(&ExclusiveLockedDir<'_>) -> Result<T>,
{
    let file = clone_directory_descriptor(dir)?;
    let identity = file_identity(&file, dir.path())?;
    let held = HeldDirectory::claim(file, identity, dir.path())?;
    acquire_directory_lock(&held.file, dir.path())?;
    f(&ExclusiveLockedDir {
        file: &held.file,
        path: dir.path(),
        scope: dir.scope(),
    })
}

#[cfg(unix)]
fn acquire_directory_lock(file: &File, path: &Path) -> Result<()> {
    match rustix::fs::flock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => return Ok(()),
        Err(Errno::WOULDBLOCK) => {}
        Err(error) => return Err(lock_failure(path, error)),
    }
    tracing::warn!("{}", format_lock_contention(path));
    wait_for_directory_lock(file, path)
}

#[cfg(unix)]
fn wait_for_directory_lock(file: &File, path: &Path) -> Result<()> {
    let deadline = Instant::now() + DIRECTORY_LOCK_ACQUIRE_TIMEOUT;
    let mut interval = DIRECTORY_LOCK_RETRY_MIN_INTERVAL;
    loop {
        if Instant::now() >= deadline {
            return Err(lock_timeout(path));
        }
        std::thread::sleep(interval);
        interval = (interval * 2).min(DIRECTORY_LOCK_RETRY_MAX_INTERVAL);
        match rustix::fs::flock(file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(()),
            Err(Errno::WOULDBLOCK) => {}
            Err(error) => return Err(lock_failure(path, error)),
        }
    }
}

#[cfg(unix)]
fn lock_failure(path: &Path, error: Errno) -> Error {
    let source = std::io::Error::from(error);
    Error::build_io_error_with_source(
        format!(
            "Failed to lock directory {}: {}",
            format_path_relative_to_cwd(path),
            source
        ),
        source,
    )
}

fn format_lock_contention(path: &Path) -> String {
    format!(
        "Waiting for the lock on {} to be released",
        format_path_relative_to_cwd(path)
    )
}

fn nested_lock_error(path: &Path, held: &Path) -> Error {
    Error::build_invalid_operation_error(format!(
        "refusing to lock {} while {} is already locked on this thread: nested directory locks are not allowed",
        format_path_relative_to_cwd(path),
        format_path_relative_to_cwd(held)
    ))
}

fn lock_timeout(path: &Path) -> Error {
    Error::build_io_error(format!(
        "Gave up waiting for the lock on {} after {} seconds; run the command again after the other kapsaro writer finishes",
        format_path_relative_to_cwd(path),
        DIRECTORY_LOCK_ACQUIRE_TIMEOUT.as_secs()
    ))
}

#[cfg(unix)]
fn clone_directory_descriptor<D>(dir: &D) -> Result<File>
where
    D: DirectoryFd,
{
    use rustix::fs::{openat, Mode};

    openat(
        dir.file(),
        c".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        let source = std::io::Error::from(error);
        Error::build_io_error_with_source(
            format!("Failed to reopen directory descriptor: {}", source),
            source,
        )
    })
}

#[cfg(test)]
#[path = "../../../tests/test_support/support_fs_lock_test_support.rs"]
pub(crate) mod lock_test_support;

#[cfg(test)]
#[path = "../../../tests/unit/internal/support_fs_lock_test.rs"]
mod support_fs_lock_test;
