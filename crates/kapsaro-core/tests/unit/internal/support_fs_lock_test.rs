// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for support/fs/lock module
//!
//! Tests for file locking utilities.

use crate::support::fs::lock::lock_test_support::with_locked_workspace_dir;
use crate::support::fs::lock::{
    probe_directory_lock_exclusion, with_exclusive_locked_directory, with_shared_locked_directory,
    LockExclusionProbe,
};
use crate::support::fs::relative::{open_dir_following, DirectoryScope, OpenDir};
use std::fs;
use std::path::Path;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

#[test]
fn test_with_locked_dir_basic_operation_and_return_value() {
    let temp_dir = TempDir::new().unwrap();
    let result = with_locked_workspace_dir(temp_dir.path(), |_| Ok::<i32, kapsaro_core::Error>(42));
    assert_eq!(result.unwrap(), 42);
}

#[test]
fn test_with_locked_dir_propagates_error() {
    let temp_dir = TempDir::new().unwrap();
    let result: kapsaro_core::Result<()> = with_locked_workspace_dir(temp_dir.path(), |_| {
        Err(kapsaro_core::Error::build_config_error(
            "dir lock error".to_string(),
        ))
    });
    assert!(result.is_err());
}

/// Two threads that ask for the same workspace lock both get to run their body.
///
/// The lock hands the directory to one of them at a time, so the one that has
/// to wait is served once the other is out rather than being refused or losing
/// its work. Which of them goes first is not fixed, and the exclusion itself is
/// measured by [`LockContention`], which observes the second lock while the
/// first is still held.
#[test]
fn test_with_locked_dir_runs_the_body_of_every_thread_that_takes_the_lock() {
    use std::sync::Barrier;

    let temp_dir = TempDir::new().unwrap();
    let dir_path = temp_dir.path().to_path_buf();
    let barrier = Arc::new(Barrier::new(2));
    let counter = Arc::new(std::sync::Mutex::new(0u32));

    let dir_clone = dir_path.clone();
    let barrier_clone = Arc::clone(&barrier);
    let counter_clone = Arc::clone(&counter);

    let handle = thread::spawn(move || {
        barrier_clone.wait();
        with_locked_workspace_dir(&dir_clone, |_| {
            let mut c = counter_clone.lock().unwrap();
            *c += 1;
            Ok::<(), kapsaro_core::Error>(())
        })
        .unwrap();
    });

    barrier.wait();
    with_locked_workspace_dir(&dir_path, |_| {
        let mut c = counter.lock().unwrap();
        *c += 1;
        Ok::<(), kapsaro_core::Error>(())
    })
    .unwrap();

    handle.join().unwrap();
    assert_eq!(*counter.lock().unwrap(), 2);
}

#[test]
fn test_shared_directory_locks_can_be_held_concurrently() {
    let temp_dir = TempDir::new().unwrap();
    let first_dir = open_dir_following(temp_dir.path(), DirectoryScope::LocalState).unwrap();
    let second_dir = open_dir_following(temp_dir.path(), DirectoryScope::LocalState).unwrap();
    let (acquired_tx, acquired_rx) = mpsc::channel();

    with_shared_locked_directory(&first_dir, |_| {
        let worker = thread::spawn(move || {
            with_shared_locked_directory(&second_dir, |_| {
                acquired_tx.send(()).unwrap();
                Ok(())
            })
            .unwrap();
        });
        acquired_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("a second shared lock must be acquired concurrently");
        worker.join().unwrap();
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_exclusive_directory_lock_waits_for_shared_lock() {
    let temp_dir = TempDir::new().unwrap();
    LockContention {
        held: hold_shared_lock,
        held_directory: open_lock_target(&temp_dir),
        contending: hold_exclusive_lock,
        contending_directory: open_lock_target(&temp_dir),
        blocked_reason: "an exclusive lock must wait while a shared lock is held",
        released_reason: "the exclusive lock must be acquired after shared lock release",
    }
    .assert_contending_lock_waits();
}

#[test]
fn test_shared_directory_lock_waits_for_exclusive_lock() {
    let temp_dir = TempDir::new().unwrap();
    LockContention {
        held: hold_exclusive_lock,
        held_directory: open_lock_target(&temp_dir),
        contending: hold_shared_lock,
        contending_directory: open_lock_target(&temp_dir),
        blocked_reason: "a shared lock must wait while an exclusive lock is held",
        released_reason: "the shared lock must be acquired after exclusive lock release",
    }
    .assert_contending_lock_waits();
}

#[test]
fn test_exclusive_directory_lock_waits_on_same_opened_directory() {
    let temp_dir = TempDir::new().unwrap();
    let directory = open_lock_target(&temp_dir);
    LockContention {
        held: hold_shared_lock,
        held_directory: Arc::clone(&directory),
        contending: hold_exclusive_lock,
        contending_directory: directory,
        blocked_reason: "locks taken through one opened directory must contend, \
                         not share the descriptor's lock",
        released_reason: "the exclusive lock must be acquired once the shared lock \
                          on the same opened directory is released",
    }
    .assert_contending_lock_waits();
}

/// Run `body` while a lock of one kind is held on `dir`.
///
/// Erasing both lock kinds to one signature is what lets a single contention
/// harness drive every pairing of shared and exclusive locks.
type LockOperation = fn(&OpenDir, &mut dyn FnMut()) -> kapsaro_core::Result<()>;

fn hold_shared_lock(dir: &OpenDir, body: &mut dyn FnMut()) -> kapsaro_core::Result<()> {
    with_shared_locked_directory(dir, |_| {
        body();
        Ok(())
    })
}

fn hold_exclusive_lock(dir: &OpenDir, body: &mut dyn FnMut()) -> kapsaro_core::Result<()> {
    with_exclusive_locked_directory(dir, |_| {
        body();
        Ok(())
    })
}

fn open_lock_target(temp_dir: &TempDir) -> Arc<OpenDir> {
    Arc::new(open_dir_following(temp_dir.path(), DirectoryScope::LocalState).unwrap())
}

/// How long a contending lock is given to prove it is blocked. Long enough that
/// a lock that was wrongly granted is observed, short enough to stay cheap.
const BLOCKED_OBSERVATION: Duration = Duration::from_millis(300);

/// How long an operation that must eventually succeed is waited for.
const PROGRESS_TIMEOUT: Duration = Duration::from_secs(5);

/// One contention scenario: `held` is taken and kept while `contending` is
/// attempted from another thread, and must not be granted until `held` is out.
///
/// Passing the same `Arc` as both directories covers locks taken through a
/// single opened directory; two separate ones cover independent descriptors.
struct LockContention {
    held: LockOperation,
    held_directory: Arc<OpenDir>,
    contending: LockOperation,
    contending_directory: Arc<OpenDir>,
    blocked_reason: &'static str,
    released_reason: &'static str,
}

impl LockContention {
    fn assert_contending_lock_waits(self) {
        let (started_tx, started_rx) = mpsc::channel();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let mut worker = None;

        (self.held)(&self.held_directory, &mut || {
            worker = Some(self.spawn_contender(started_tx.clone(), acquired_tx.clone()));
            started_rx.recv_timeout(PROGRESS_TIMEOUT).unwrap();
            assert!(
                acquired_rx.recv_timeout(BLOCKED_OBSERVATION).is_err(),
                "{}",
                self.blocked_reason
            );
        })
        .unwrap();

        acquired_rx
            .recv_timeout(PROGRESS_TIMEOUT)
            .expect(self.released_reason);
        worker
            .expect("the contending thread was spawned")
            .join()
            .unwrap();
    }

    fn spawn_contender(
        &self,
        started_tx: mpsc::Sender<()>,
        acquired_tx: mpsc::Sender<()>,
    ) -> thread::JoinHandle<()> {
        let contending = self.contending;
        let directory = Arc::clone(&self.contending_directory);
        thread::spawn(move || {
            started_tx.send(()).unwrap();
            contending(&directory, &mut || acquired_tx.send(()).unwrap()).unwrap();
        })
    }
}

/// The notice printed before a command stalls names the directory being waited
/// on and leaves open who is holding it: another process is the usual case, but
/// a second thread of this process contends in exactly the same way.
#[test]
fn test_lock_contention_notice_names_the_directory_without_blaming_a_process() {
    let path = Path::new("/tmp/.kapsaro/keys");

    let notice = super::describe_lock_contention(path);

    assert!(notice.contains("keys"), "the notice names the directory");
    assert!(
        !notice.contains("process"),
        "the notice must not claim a process holds the lock: {notice}"
    );
}

/// A wait that reaches its bound ends in a failure that says what to look at,
/// rather than in a command that never returns.
#[test]
fn test_lock_timeout_names_the_directory_and_what_to_do() {
    let error = super::lock_timeout(Path::new("/tmp/.kapsaro/keys"));

    let message = error.format_user_message();
    assert!(message.contains("keys"), "the failure names the directory");
    assert!(
        message.contains("holding"),
        "the failure sends the operator to the holder: {message}"
    );
}

/// A workspace lock that finds the directory already locked waits it out, which
/// is the path the contention notice is reported on. The wait has to end in the
/// lock being granted rather than in a failure.
#[test]
fn test_workspace_directory_lock_waits_for_a_held_workspace_lock() {
    let temp_dir = TempDir::new().unwrap();
    let dir_path = temp_dir.path().to_path_buf();
    let (started_tx, started_rx) = mpsc::channel();
    let (acquired_tx, acquired_rx) = mpsc::channel();
    let mut worker = None;

    with_locked_workspace_dir(&dir_path, |_| {
        let contended_path = dir_path.clone();
        worker = Some(thread::spawn(move || {
            started_tx.send(()).unwrap();
            with_locked_workspace_dir(&contended_path, |_| {
                acquired_tx.send(()).unwrap();
                Ok::<(), kapsaro_core::Error>(())
            })
            .unwrap();
        }));
        started_rx.recv_timeout(PROGRESS_TIMEOUT).unwrap();
        assert!(
            acquired_rx.recv_timeout(BLOCKED_OBSERVATION).is_err(),
            "a second workspace lock must wait while the first one is held"
        );
        Ok::<(), kapsaro_core::Error>(())
    })
    .unwrap();

    acquired_rx
        .recv_timeout(PROGRESS_TIMEOUT)
        .expect("the workspace lock must be granted once the held one is released");
    worker
        .expect("the contending thread was spawned")
        .join()
        .unwrap();
}

/// A lock refused for a reason other than contention carries the operating
/// system error out, so an operator can tell a permission problem from a mount
/// that no longer answers.
#[cfg(unix)]
#[test]
fn test_lock_failure_carries_the_operating_system_error() {
    let error = super::lock_failure(Path::new("/tmp/.kapsaro/keys"), rustix::io::Errno::ACCESS);

    assert!(error.format_user_message().contains("Failed to lock"));
    let source = std::error::Error::source(&error).expect("the lock failure keeps its cause");
    let io_error = source
        .downcast_ref::<std::io::Error>()
        .expect("the cause is the operating system error");
    assert_eq!(io_error.raw_os_error(), Some(libc::EACCES));
}

/// A directory this thread already holds is refused rather than waited on.
///
/// The second lock is taken on its own descriptor, so nothing in the kernel
/// connects it to the first and the wait would never end. The refusal is
/// immediate, which is what turns a hang into a reported caller mistake.
#[test]
fn test_relocking_one_directory_on_one_thread_is_refused() {
    let temp_dir = TempDir::new().unwrap();
    let outer = open_dir_following(temp_dir.path(), DirectoryScope::LocalState).unwrap();
    let inner = open_dir_following(temp_dir.path(), DirectoryScope::LocalState).unwrap();

    let error = with_exclusive_locked_directory(&outer, |_| {
        with_exclusive_locked_directory(&inner, |_| Ok::<(), kapsaro_core::Error>(()))
    })
    .expect_err("a second lock on one directory would wait on the first forever");

    assert!(
        error.format_user_message().contains("twice on one thread"),
        "the refusal names the reentrant take: {}",
        error.format_user_message()
    );
}

/// A shared lock taken inside an exclusive one on the same directory is the
/// same deadlock, so both kinds are held against the one registry.
#[test]
fn test_reentrant_shared_lock_inside_an_exclusive_lock_is_refused() {
    let temp_dir = TempDir::new().unwrap();
    let directory = open_dir_following(temp_dir.path(), DirectoryScope::LocalState).unwrap();

    let error = with_exclusive_locked_directory(&directory, |_| {
        with_shared_locked_directory(&directory, |_| Ok::<(), kapsaro_core::Error>(()))
    })
    .expect_err("a nested lock on one directory would wait on the outer one forever");

    assert!(error.format_user_message().contains("twice on one thread"));
}

/// The record of what this thread holds is cleared when the lock goes out of
/// scope, so a command that locks the same directory once per step still works.
#[test]
fn test_one_directory_can_be_locked_again_after_the_first_lock_is_released() {
    let temp_dir = TempDir::new().unwrap();
    let directory = open_dir_following(temp_dir.path(), DirectoryScope::LocalState).unwrap();

    for _ in 0..3 {
        with_exclusive_locked_directory(&directory, |_| Ok::<(), kapsaro_core::Error>(())).unwrap();
    }
}

/// A workspace lock with a local state lock inside it is the one nesting this
/// module allows, and it is exactly the workspace-then-trust order commands take.
#[test]
fn test_a_local_state_lock_nests_inside_a_workspace_lock() {
    let temp_dir = TempDir::new().unwrap();
    let workspace = temp_dir.path().join("workspace");
    let local_state = temp_dir.path().join("local-state");
    fs::create_dir(&workspace).unwrap();
    fs::create_dir(&local_state).unwrap();
    let inner = open_dir_following(&local_state, DirectoryScope::LocalState).unwrap();

    with_locked_workspace_dir(&workspace, |_| {
        with_exclusive_locked_directory(&inner, |_| Ok::<(), kapsaro_core::Error>(()))
    })
    .unwrap();
}

/// Local state is the innermost lock, so a thread holding one has nothing left
/// it may take. Reaching back out to a workspace lock from there is the order a
/// command going the usual way round would deadlock against.
#[test]
fn test_a_workspace_lock_inside_a_local_state_lock_is_refused() {
    let temp_dir = TempDir::new().unwrap();
    let workspace = temp_dir.path().join("workspace");
    let local_state = temp_dir.path().join("local-state");
    fs::create_dir(&workspace).unwrap();
    fs::create_dir(&local_state).unwrap();
    let inner = open_dir_following(&local_state, DirectoryScope::LocalState).unwrap();

    let error = with_exclusive_locked_directory(&inner, |_| {
        with_locked_workspace_dir(&workspace, |_| Ok::<(), kapsaro_core::Error>(()))
    })
    .expect_err("local state is the innermost lock");

    let message = error.format_user_message();
    assert!(message.contains("innermost lock"), "{message}");
    assert!(message.contains("local-state"), "{message}");
}

/// The keystore and the local trust store are both local state, and a command
/// holding one of them while taking the other is the second way the order
/// breaks: two commands doing it in opposite orders wait on each other.
#[test]
fn test_two_local_state_locks_held_at_once_are_refused() {
    let temp_dir = TempDir::new().unwrap();
    fs::create_dir(temp_dir.path().join("keys")).unwrap();
    fs::create_dir(temp_dir.path().join("trust")).unwrap();
    let keys =
        open_dir_following(&temp_dir.path().join("keys"), DirectoryScope::LocalState).unwrap();
    let trust =
        open_dir_following(&temp_dir.path().join("trust"), DirectoryScope::LocalState).unwrap();

    let error = with_exclusive_locked_directory(&keys, |_| {
        with_shared_locked_directory(&trust, |_| Ok::<(), kapsaro_core::Error>(()))
    })
    .expect_err("two local state locks must not be held at once");

    assert!(
        error.format_user_message().contains("innermost lock"),
        "{}",
        error.format_user_message()
    );
}

/// Workspace locks say nothing about local state, so two of them still nest:
/// that is how a command reaches a member document below a locked workspace.
#[test]
fn test_two_workspace_locks_still_nest() {
    let temp_dir = TempDir::new().unwrap();
    fs::create_dir(temp_dir.path().join("first")).unwrap();
    fs::create_dir(temp_dir.path().join("second")).unwrap();

    with_locked_workspace_dir(&temp_dir.path().join("first"), |_| {
        with_locked_workspace_dir(&temp_dir.path().join("second"), |_| {
            Ok::<(), kapsaro_core::Error>(())
        })
    })
    .unwrap();
}

/// An exclusive lock on ordinary local storage is granted, so every command
/// that takes one runs on the storage the tests themselves use.
#[cfg(unix)]
#[test]
fn test_exclusive_lock_is_granted_on_local_storage() {
    let temp_dir = TempDir::new().unwrap();
    let directory = open_dir_following(temp_dir.path(), DirectoryScope::LocalState).unwrap();

    with_exclusive_locked_directory(&directory, |_| Ok::<(), kapsaro_core::Error>(())).unwrap();
}

/// Local storage arbitrates `flock`, so the second lock the probe asks for is
/// refused and the measurement reports the exclusion as effective.
#[cfg(unix)]
#[test]
fn test_lock_exclusion_probe_reports_local_storage_as_exclusive() {
    let temp_dir = TempDir::new().unwrap();
    let directory = open_dir_following(temp_dir.path(), DirectoryScope::LocalState).unwrap();

    let probe = probe_directory_lock_exclusion(&directory);

    assert_eq!(probe, LockExclusionProbe::Exclusive, "{probe:?}");
}

/// The probe takes two locks of its own, so a directory it measured has to be
/// lockable straight afterwards.
#[cfg(unix)]
#[test]
fn test_lock_exclusion_probe_releases_every_lock_it_took() {
    let temp_dir = TempDir::new().unwrap();
    let measured = open_dir_following(temp_dir.path(), DirectoryScope::LocalState).unwrap();

    probe_directory_lock_exclusion(&measured);

    let directory = open_dir_following(temp_dir.path(), DirectoryScope::LocalState).unwrap();
    with_exclusive_locked_directory(&directory, |_| Ok::<(), kapsaro_core::Error>(())).unwrap();
}

/// A lock somebody else already holds makes the second take say nothing about
/// the filesystem, so the measurement reports that it could not decide.
#[cfg(unix)]
#[test]
fn test_lock_exclusion_probe_reports_a_directory_somebody_else_holds() {
    let temp_dir = TempDir::new().unwrap();
    let directory = open_dir_following(temp_dir.path(), DirectoryScope::LocalState).unwrap();

    let probe = with_exclusive_locked_directory(&directory, |locked| {
        Ok::<LockExclusionProbe, kapsaro_core::Error>(probe_directory_lock_exclusion(locked))
    })
    .unwrap();

    assert_eq!(probe, LockExclusionProbe::Contended, "{probe:?}");
}

/// The measurement follows the descriptor it was handed, so a directory renamed
/// out of the way while the probe runs is still the directory measured.
///
/// Nothing resolves the name a second time: both descriptions the probe locks are
/// opened from the one it was given.
#[cfg(unix)]
#[test]
fn test_lock_exclusion_probe_measures_the_directory_the_descriptor_holds() {
    let temp_dir = TempDir::new().unwrap();
    let measured = temp_dir.path().join("measured");
    fs::create_dir(&measured).unwrap();
    let directory = open_dir_following(&measured, DirectoryScope::LocalState).unwrap();
    fs::rename(&measured, temp_dir.path().join("renamed")).unwrap();

    let probe = probe_directory_lock_exclusion(&directory);

    assert_eq!(probe, LockExclusionProbe::Exclusive, "{probe:?}");
}
