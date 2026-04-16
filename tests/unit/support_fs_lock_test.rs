// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for support/fs/lock module
//!
//! Tests for file locking utilities.

use secretenv::support::fs::lock::with_file_lock;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

use crate::test_utils::with_temp_cwd;

#[test]
fn test_with_file_lock() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");

    let result = with_file_lock(&file_path, || {
        fs::write(&file_path, "locked content").unwrap();
        Ok(())
    });

    assert!(result.is_ok());
    assert!(file_path.exists());
    let content = fs::read_to_string(&file_path).unwrap();
    assert_eq!(content, "locked content");
}

#[test]
fn test_with_file_lock_returns_value() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");

    let result = with_file_lock(&file_path, || Ok::<i32, secretenv::Error>(42));

    assert_eq!(result.unwrap(), 42);
}

#[test]
fn test_with_file_lock_propagates_error() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");

    let result: Result<(), secretenv::Error> = with_file_lock(&file_path, || {
        Err(secretenv::Error::Config {
            message: "Test error".to_string(),
        })
    });

    assert!(result.is_err());
}

#[test]
fn test_with_file_lock_creates_parent_dir() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("a/b/test.txt");
    let parent_dir = file_path.parent().unwrap();

    assert!(
        !parent_dir.exists(),
        "Precondition: parent dir must not exist"
    );

    let result = with_file_lock(&file_path, || {
        // If with_file_lock doesn't create the parent directory, this write
        // will fail and the test will catch it.
        fs::write(&file_path, "locked content").unwrap();
        Ok::<(), secretenv::Error>(())
    });

    assert!(result.is_ok());
    assert!(parent_dir.exists());
    assert!(file_path.exists());
}

#[cfg(unix)]
#[test]
fn test_lock_file_created_with_0600() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.toml");

    with_file_lock(&file_path, || {
        let lock_path = temp_dir.path().join(".test.toml.lock");
        assert!(lock_path.exists());
        let mode = fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        Ok(())
    })
    .unwrap();
}

#[test]
fn test_with_file_lock_accepts_relative_filename_in_current_directory() {
    let temp_dir = TempDir::new().unwrap();

    with_temp_cwd(temp_dir.path(), || {
        let result = with_file_lock(Path::new("relative.txt"), || {
            fs::write("relative.txt", "locked content").unwrap();
            Ok::<(), secretenv::Error>(())
        });

        assert!(result.is_ok());
        assert!(temp_dir.path().join("relative.txt").exists());
        assert!(temp_dir.path().join(".relative.txt.lock").exists());
    });
}
