// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests the exclusive-only directory lock and its bounded nesting contract.
//! Covers writer serialization, release, and same-thread nesting refusal.

use super::with_exclusive_locked_directory;
use crate::support::fs::relative::{open_dir_following, DirectoryScope};
use crate::ErrorKind;
use std::sync::mpsc;
use std::time::Duration;
use tempfile::TempDir;

#[test]
fn test_exclusive_lock_serializes_writers() {
    let temp = TempDir::new().unwrap();
    let first = open_dir_following(temp.path(), DirectoryScope::Generic).unwrap();
    let second = open_dir_following(temp.path(), DirectoryScope::Generic).unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (acquired_tx, acquired_rx) = mpsc::channel();

    with_exclusive_locked_directory(&first, |_| {
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            with_exclusive_locked_directory(&second, |_| {
                acquired_tx.send(()).unwrap();
                Ok(())
            })
            .unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(acquired_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err());
        drop(worker);
        Ok(())
    })
    .unwrap();
    acquired_rx.recv_timeout(Duration::from_secs(2)).unwrap();
}

#[test]
fn test_exclusive_lock_can_be_reacquired_after_release() {
    let temp = TempDir::new().unwrap();
    let directory = open_dir_following(temp.path(), DirectoryScope::Generic).unwrap();

    with_exclusive_locked_directory(&directory, |_| Ok(())).unwrap();
    with_exclusive_locked_directory(&directory, |_| Ok(())).unwrap();
}

#[test]
fn test_exclusive_lock_rejects_any_same_thread_nesting() {
    let temp = TempDir::new().unwrap();
    let other = TempDir::new().unwrap();
    let first = open_dir_following(temp.path(), DirectoryScope::Generic).unwrap();
    let second = open_dir_following(other.path(), DirectoryScope::LocalState).unwrap();

    let error = with_exclusive_locked_directory(&first, |_| {
        with_exclusive_locked_directory(&second, |_| Ok(()))
    })
    .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert!(error
        .format_user_message()
        .contains("nested directory locks are not allowed"));
}

#[test]
fn test_exclusive_lock_returns_closure_result() {
    let temp = TempDir::new().unwrap();
    let directory = open_dir_following(temp.path(), DirectoryScope::Generic).unwrap();

    let value = with_exclusive_locked_directory(&directory, |_| Ok::<_, crate::Error>(42)).unwrap();

    assert_eq!(value, 42);
}
