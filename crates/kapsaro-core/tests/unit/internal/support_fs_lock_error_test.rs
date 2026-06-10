// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Error-path unit tests for support/fs/lock module.
//!
//! Complements support_fs_lock_test.rs (happy paths) by exercising
//! failure branches of with_file_lock.

use crate::support::fs::lock::with_file_lock;
use kapsaro_core::{Error, ErrorKind};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn test_with_file_lock_empty_path_fails() {
    let err = with_file_lock(Path::new(""), || Ok::<(), Error>(()))
        .expect_err("empty path has no file_name component");
    assert_eq!(err.kind(), ErrorKind::Io);
    assert!(
        err.format_user_message().contains("Invalid file path"),
        "unexpected message: {}",
        err.format_user_message()
    );
}

#[test]
fn test_with_file_lock_root_path_fails() {
    let err = with_file_lock(Path::new("/"), || Ok::<(), Error>(()))
        .expect_err("root path has no file_name component");
    assert_eq!(err.kind(), ErrorKind::Io);
    assert!(
        err.format_user_message().contains("Invalid file path"),
        "unexpected message: {}",
        err.format_user_message()
    );
}

#[test]
fn test_with_file_lock_parent_is_file_fails() {
    let temp_dir = TempDir::new().unwrap();
    let file_as_parent = temp_dir.path().join("plain_file");
    fs::write(&file_as_parent, b"blocker").unwrap();

    let target = file_as_parent.join("child.txt");
    let err = with_file_lock(&target, || Ok::<(), Error>(()))
        .expect_err("parent of lock file is a regular file, expected error");

    // Either `ensure_dir_restricted` fails first with "Failed to create directory
    // for lock file", or `OpenOptions::open` fails with "Failed to open lock file".
    assert_eq!(err.kind(), ErrorKind::Io);
    let message = err.format_user_message();
    let ok = message.contains("Failed to create directory for lock file")
        || message.contains("Failed to open lock file");
    assert!(ok, "unexpected message: {}", message);
}

#[test]
fn test_with_file_lock_closure_not_invoked_on_path_error() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static CALLED: AtomicBool = AtomicBool::new(false);

    let _ = with_file_lock(Path::new(""), || {
        CALLED.store(true, Ordering::SeqCst);
        Ok::<(), Error>(())
    });
    assert!(
        !CALLED.load(Ordering::SeqCst),
        "closure must not run when path validation fails"
    );
}
