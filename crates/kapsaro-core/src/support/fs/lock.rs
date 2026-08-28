// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File locking utilities.
//! Provides typed shared-read and exclusive-write directory capabilities.
//!
//! A directory lock keeps two commands from doing the same work at the same
//! time. It is an optimisation rather than the wall that keeps stored state
//! intact: `flock` excludes only where the filesystem underneath arbitrates it,
//! and no lock taken here can be assumed to have excluded anyone. Whether it
//! does is measured by [`probe_directory_lock_exclusion`] and reported by the
//! diagnostic command, so an operator learns what the lock is worth on their
//! storage instead of an update being refused on a guess about the mount.
//!
//! Directory locks are taken on a freshly opened descriptor for the directory,
//! so they contend within one process exactly as they do across processes: the
//! kernel would let a thread wait on a directory it already holds. The
//! identities held on the current thread are recorded here and a second take is
//! refused instead. Callers still acquire once at the top of an operation and
//! pass the guard down; functions named `*_locked` expect an already locked
//! directory and must never take one themselves.
//!
//! Local state is the innermost lock, and that is the one rule enforced here: a
//! thread holding a lock on a local state directory is refused any further lock,
//! whichever directory it names. That covers both ways the rule can break —
//! reaching back out to a workspace lock, and holding two local state locks such
//! as the keystore's and the trust store's at once. The scope the directory was
//! opened with is what says which of the two a lock is.
//!
//! Workspace locks say nothing about local state, so any number of them nest.
//! That is deliberate: reaching a member document below a locked members root
//! means holding both. Their order is the caller's to keep. Nothing here checks
//! it, and two commands taking one pair in opposite orders wait on each other
//! until [`DIRECTORY_LOCK_ACQUIRE_TIMEOUT`] runs out. That bound is the safety
//! net rather than the diagnosis: what the operator sees is a command that
//! stalls for thirty seconds and then fails on whichever lock it was waiting
//! for, which does not name the pair or the order that produced it.

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
use std::marker::PhantomData;
use std::path::Path;
use std::time::Instant;

#[cfg(unix)]
use rustix::fs::{FlockOperation, OFlags};
#[cfg(unix)]
use rustix::io::Errno;

#[derive(Debug)]
pub(crate) struct SharedLock;

#[derive(Debug)]
pub(crate) struct ExclusiveLock;

#[derive(Debug)]
pub(crate) struct LockedDir<'a, Mode> {
    file: &'a File,
    path: &'a Path,
    scope: DirectoryScope,
    mode: PhantomData<Mode>,
}

pub(crate) type SharedLockedDir<'a> = LockedDir<'a, SharedLock>;
pub(crate) type ExclusiveLockedDir<'a> = LockedDir<'a, ExclusiveLock>;

mod private {
    pub trait ReadSealed {}
    pub trait LockTargetSealed {}
}

pub(crate) trait ReadLockedDirectory: DirectoryFd + private::ReadSealed {}

pub(crate) trait LockTargetDirectory: DirectoryFd + private::LockTargetSealed {}

impl<Mode> DirectoryFd for LockedDir<'_, Mode> {
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

impl<Mode> private::ReadSealed for LockedDir<'_, Mode> {}
impl<Mode> ReadLockedDirectory for LockedDir<'_, Mode> {}

impl private::LockTargetSealed for OpenDir {}
impl private::LockTargetSealed for AnchoredDir {}
impl LockTargetDirectory for OpenDir {}
impl LockTargetDirectory for AnchoredDir {}

/// What one directory lock asks the filesystem for.
#[cfg(unix)]
trait LockKind {
    /// The `flock` operation that takes this lock without waiting.
    const ACQUIRE: FlockOperation;
}

#[cfg(unix)]
impl LockKind for SharedLock {
    const ACQUIRE: FlockOperation = FlockOperation::NonBlockingLockShared;
}

#[cfg(unix)]
impl LockKind for ExclusiveLock {
    const ACQUIRE: FlockOperation = FlockOperation::NonBlockingLockExclusive;
}

// One entry per directory this thread currently holds a lock on. A lock is
// taken on a descriptor opened for it, so nothing in the kernel connects two
// takes of the same directory on one thread and the second would wait on the
// first forever. The identity is recorded here so that take is refused instead.
#[cfg(unix)]
thread_local! {
    static HELD_DIRECTORY_LOCKS: RefCell<Vec<HeldLock>> = const { RefCell::new(Vec::new()) };
}

/// One lock this thread holds: which directory, and what it is a lock on.
///
/// The path is kept so a refusal can name the lock that is already held. It is
/// the path the lock was taken through rather than a resolved one, which is the
/// spelling the caller would recognise.
#[cfg(unix)]
struct HeldLock {
    identity: EntryIdentity,
    scope: DirectoryScope,
    path: std::path::PathBuf,
}

/// A directory descriptor this thread holds a lock on until it is dropped.
#[cfg(unix)]
struct HeldDirectory {
    file: File,
    identity: EntryIdentity,
}

#[cfg(unix)]
impl HeldDirectory {
    /// Record the directory as locked on this thread, refusing a take that
    /// would deadlock or break the one nesting order this module allows.
    ///
    /// The reentrant take is judged first: it is the same directory twice and
    /// is a mistake whatever the order says, so naming the order instead would
    /// send the caller looking for the wrong thing.
    fn claim(
        file: File,
        identity: EntryIdentity,
        scope: DirectoryScope,
        path: &Path,
    ) -> Result<Self> {
        HELD_DIRECTORY_LOCKS.with(|held| {
            let mut held = held.borrow_mut();
            if held.iter().any(|entry| entry.identity == identity) {
                return Err(reentrant_lock_error(path));
            }
            if let Some(inner) = innermost_held_lock(&held) {
                return Err(lock_order_error(path, &inner.path));
            }
            held.push(HeldLock {
                identity,
                scope,
                path: path.to_path_buf(),
            });
            Ok(())
        })?;
        Ok(Self { file, identity })
    }
}

/// The held lock nothing may be taken inside, when this thread holds one.
///
/// Local state is the innermost lock: a workspace lock is taken first and the
/// local trust directory's lock inside it, and nothing goes the other way. So a
/// thread holding a local state lock has nothing left it may reach for, and one
/// holding only workspace locks may still go inward.
#[cfg(unix)]
fn innermost_held_lock(held: &[HeldLock]) -> Option<&HeldLock> {
    held.iter()
        .find(|entry| entry.scope == DirectoryScope::LocalState)
}

#[cfg(unix)]
impl Drop for HeldDirectory {
    fn drop(&mut self) {
        HELD_DIRECTORY_LOCKS.with(|held| {
            let mut held = held.borrow_mut();
            if let Some(position) = held
                .iter()
                .position(|entry| entry.identity == self.identity)
            {
                held.swap_remove(position);
            }
        });
    }
}

/// Lock an already opened directory for concurrent reading.
#[cfg(unix)]
pub(crate) fn with_shared_locked_directory<T, D, F>(dir: &D, f: F) -> Result<T>
where
    D: LockTargetDirectory,
    F: FnOnce(&SharedLockedDir<'_>) -> Result<T>,
{
    let file = clone_directory_descriptor(dir)?;
    with_directory_lock::<T, SharedLock, F>(file, dir.path(), dir.scope(), f)
}

/// Lock an already opened directory for exclusive mutation.
#[cfg(unix)]
pub(crate) fn with_exclusive_locked_directory<T, D, F>(dir: &D, f: F) -> Result<T>
where
    D: LockTargetDirectory,
    F: FnOnce(&ExclusiveLockedDir<'_>) -> Result<T>,
{
    let file = clone_directory_descriptor(dir)?;
    with_directory_lock::<T, ExclusiveLock, F>(file, dir.path(), dir.scope(), f)
}

/// Take one directory lock and run the caller's body under it.
///
/// The identity is read before anything blocks, so a directory this thread
/// already holds is reported as the caller's mistake instead of stalling the
/// command until the acquisition times out.
#[cfg(unix)]
fn with_directory_lock<T, M, F>(file: File, path: &Path, scope: DirectoryScope, f: F) -> Result<T>
where
    M: LockKind,
    F: FnOnce(&LockedDir<'_, M>) -> Result<T>,
{
    let identity = file_identity(&file, path)?;
    let held = HeldDirectory::claim(file, identity, scope, path)?;
    acquire_directory_lock::<M>(&held.file, path)?;
    let locked = LockedDir {
        file: &held.file,
        path,
        scope,
        mode: PhantomData,
    };
    f(&locked)
}

/// Take the lock, waiting only when something else already holds it.
#[cfg(unix)]
fn acquire_directory_lock<M>(file: &File, path: &Path) -> Result<()>
where
    M: LockKind,
{
    match rustix::fs::flock(file, M::ACQUIRE) {
        Ok(()) => return Ok(()),
        Err(Errno::WOULDBLOCK) => {}
        Err(error) => return Err(lock_failure(path, error)),
    }
    report_lock_contention(path);
    wait_for_directory_lock::<M>(file, path)
}

/// Retry a contended lock on a backoff, giving up rather than waiting forever.
///
/// `flock` has no timed form, so the wait is built from non-blocking attempts.
/// A bound is what keeps a lock somebody left behind from turning every later
/// command into a process that never returns and never says why.
#[cfg(unix)]
fn wait_for_directory_lock<M>(file: &File, path: &Path) -> Result<()>
where
    M: LockKind,
{
    let deadline = Instant::now() + DIRECTORY_LOCK_ACQUIRE_TIMEOUT;
    let mut interval = DIRECTORY_LOCK_RETRY_MIN_INTERVAL;
    loop {
        if Instant::now() >= deadline {
            return Err(lock_timeout(path));
        }
        std::thread::sleep(interval);
        interval = (interval * 2).min(DIRECTORY_LOCK_RETRY_MAX_INTERVAL);
        match rustix::fs::flock(file, M::ACQUIRE) {
            Ok(()) => return Ok(()),
            Err(Errno::WOULDBLOCK) => {}
            Err(error) => return Err(lock_failure(path, error)),
        }
    }
}

/// Report a lock that could not be taken, keeping the original error.
///
/// The operating system error is carried as the source rather than rebuilt from
/// its text, so the errno an operator needs to tell a permission problem from a
/// stale mount survives all the way out.
#[cfg(unix)]
fn lock_failure(path: &Path, error: Errno) -> Error {
    let source = std::io::Error::from(error);
    let message = format!(
        "Failed to lock directory {}: {}",
        format_path_relative_to_cwd(path),
        source
    );
    Error::build_io_error_with_source(message, source)
}

/// Tell the operator why the command is stalling before it waits.
fn report_lock_contention(path: &Path) {
    tracing::warn!("{}", describe_lock_contention(path));
}

/// Word the wait notice without naming who is holding the lock.
///
/// It is normally another process, but a second thread of this one contends in
/// exactly the same way, and the message must not send an operator looking for
/// a process that is not there.
fn describe_lock_contention(path: &Path) -> String {
    format!(
        "Waiting for the lock on {} to be released",
        format_path_relative_to_cwd(path)
    )
}

/// Report a lock this thread already holds, before the second take blocks.
fn reentrant_lock_error(path: &Path) -> Error {
    Error::build_invalid_operation_error(format!(
        "refusing to lock {} twice on one thread: the second lock is taken on its own descriptor \
         and would wait on the first one forever",
        format_path_relative_to_cwd(path)
    ))
}

/// Report a lock taken in an order this module does not allow.
///
/// Local state is the innermost lock, so a thread holding one has nothing left
/// it may take. A command that reached outward from there would sooner or later
/// meet one that went the usual way round, and the two would wait on each other.
fn lock_order_error(path: &Path, held: &Path) -> Error {
    Error::build_invalid_operation_error(format!(
        "refusing to lock {} while the local state directory {} is locked on this thread: local \
         state is the innermost lock, and taking another one from inside it is the order that \
         deadlocks against a command taking the two the other way round",
        format_path_relative_to_cwd(path),
        format_path_relative_to_cwd(held)
    ))
}

/// Report a lock that stayed held for longer than a command is willing to wait.
fn lock_timeout(path: &Path) -> Error {
    Error::build_io_error(format!(
        "Gave up waiting for the lock on {} after {} seconds; this may be another kapsaro command \
         still in the middle of a long operation, in which case running this again once it \
         finishes is enough, or find out which process is holding the lock and let it finish, or \
         stop it, before running this again",
        format_path_relative_to_cwd(path),
        DIRECTORY_LOCK_ACQUIRE_TIMEOUT.as_secs()
    ))
}

/// What one measurement of a directory's locking behaviour observed.
///
/// Nothing is inferred from the name of the filesystem: a mount is measured by
/// asking it for the exclusion the locks here depend on and seeing what it
/// answers.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LockExclusionProbe {
    /// A second lock on the same directory was refused, so a lock excludes.
    Exclusive,
    /// A second lock was granted while the first was held, so a lock granted
    /// here excludes nobody.
    Ineffective,
    /// The filesystem does not implement `flock` for this directory at all.
    Unsupported,
    /// Somebody already held a lock, so the second take proves nothing.
    Contended,
    /// The measurement itself could not be made.
    Unavailable { reason: String },
}

/// Measure whether a lock on `dir` excludes a second holder.
///
/// Two locks are taken deliberately, from independent open file descriptions,
/// so the registry of what this thread holds is bypassed and raw `flock` is
/// used. A filesystem that arbitrates locks refuses the second one; a mount
/// that grants both is one where every lock in this module is a no-op.
///
/// Both descriptions are opened from the descriptor the caller already holds, so
/// the measurement is about that directory and not about whatever its name
/// resolves to while the measurement runs.
///
/// Both locks are released before the answer is returned, so a measurement
/// never leaves a directory locked behind it.
#[cfg(unix)]
pub(crate) fn probe_directory_lock_exclusion<D>(dir: &D) -> LockExclusionProbe
where
    D: DirectoryFd,
{
    let first = match clone_directory_descriptor(dir) {
        Ok(file) => file,
        Err(error) => return probe_unavailable(error.format_user_message()),
    };
    match take_probe_lock(&first) {
        ProbeLock::Granted => {}
        ProbeLock::Refused => return LockExclusionProbe::Contended,
        ProbeLock::Unsupported => return LockExclusionProbe::Unsupported,
        ProbeLock::Failed(reason) => return probe_unavailable(reason),
    }
    let probe = probe_second_lock(&first);
    release_probe_lock(&first);
    probe
}

/// Ask for the same lock a second time, from a descriptor of its own.
#[cfg(unix)]
fn probe_second_lock(first: &File) -> LockExclusionProbe {
    let second = match clone_descriptor(first) {
        Ok(second) => second,
        Err(error) => return probe_unavailable(error.format_user_message()),
    };
    match take_probe_lock(&second) {
        ProbeLock::Refused => LockExclusionProbe::Exclusive,
        ProbeLock::Granted => {
            release_probe_lock(&second);
            LockExclusionProbe::Ineffective
        }
        ProbeLock::Unsupported => LockExclusionProbe::Unsupported,
        ProbeLock::Failed(reason) => probe_unavailable(reason),
    }
}

#[cfg(unix)]
fn probe_unavailable(reason: impl Into<String>) -> LockExclusionProbe {
    LockExclusionProbe::Unavailable {
        reason: reason.into(),
    }
}

/// How one raw `flock` attempt of the probe ended.
#[cfg(unix)]
enum ProbeLock {
    Granted,
    Refused,
    Unsupported,
    Failed(String),
}

#[cfg(unix)]
fn take_probe_lock(file: &File) -> ProbeLock {
    match rustix::fs::flock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => ProbeLock::Granted,
        Err(Errno::WOULDBLOCK) => ProbeLock::Refused,
        Err(error) if is_unsupported_operation(error) => ProbeLock::Unsupported,
        Err(error) => ProbeLock::Failed(std::io::Error::from(error).to_string()),
    }
}

/// Release a lock the probe took, whatever the release itself answers.
///
/// Closing the descriptor drops the lock as well, so a release that fails
/// leaves nothing held once the probe returns.
#[cfg(unix)]
fn release_probe_lock(file: &File) {
    let _ = rustix::fs::flock(file, FlockOperation::Unlock);
}

/// Whether the error says the filesystem has no `flock` to offer.
///
/// The two names for "not supported" hold one value on some targets, so they
/// are compared rather than matched as patterns.
///
/// `EINVAL` is not one of them: it says the operation this call passed was not a
/// valid one, which is a mistake here rather than an answer about the mount.
/// Reading it as an unsupported filesystem would send the operator to look at
/// their storage over a bug in this module, so it is left to be reported as the
/// failure it is.
#[cfg(unix)]
fn is_unsupported_operation(error: Errno) -> bool {
    error == Errno::OPNOTSUPP || error == Errno::NOTSUP
}

#[cfg(unix)]
fn clone_directory_descriptor<D>(dir: &D) -> Result<File>
where
    D: DirectoryFd,
{
    clone_descriptor(dir.file())
}

/// Open a second descriptor onto the directory an open descriptor names.
///
/// The two are independent open file descriptions, which is what lets one hold
/// a lock the other has to contend for.
#[cfg(unix)]
fn clone_descriptor(file: &File) -> Result<File> {
    use rustix::fs::{openat, Mode};

    openat(
        file,
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

// Tests reach a directory lock from a path, which production never does. The
// helper that opens the path and locks what it opened lives in the test tree and
// is registered here so every test module can use the one copy.
#[cfg(test)]
#[path = "../../../tests/unit/internal/support_fs_lock_test_support.rs"]
pub(crate) mod lock_test_support;

#[cfg(test)]
#[path = "../../../tests/unit/internal/support_fs_lock_test.rs"]
mod support_fs_lock_test;
